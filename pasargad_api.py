"""
کلاینت async برای اتصال به پنل پاسارگاد (Marzban / سازگار با API مشابه).

قابلیت‌ها:
    - احراز هویت و کش کردن توکن
    - ساخت / خواندن / ویرایش / حذف / تمدید / ریست مصرف کاربر
    - خواندن آمار سیستم و اینباندهای پنل
    - تست اتصال
    - کش کلاینت‌ها بر اساس (آدرس پنل، یوزرنیم، پسورد, ...) تا توکن بین درخواست‌ها حفظ بشه
"""

import asyncio
import json
import random
import re
import string
import time
from typing import Any

import aiohttp

GB = 1024 * 1024 * 1024

DEFAULT_PROXIES: dict[str, dict] = {
    "vless": {"flow": ""},
    "vmess": {},
    "trojan": {},
    "shadowsocks": {"method": "chacha20-ietf-poly1305"},
}

# اینباندها: دیکشنری خالی یعنی «همه‌ی اینباندهای موجود پنل»
DEFAULT_INBOUNDS: dict[str, list[str]] = {}


class PanelError(Exception):
    """هر خطایی که موقع ارتباط با پنل رخ بده (شبکه، احراز هویت، پاسخ نامعتبر و ...)"""


def sanitize_username(raw: str, fallback: str = "user") -> str:
    """نام کاربری رو به فرمت قابل‌قبول پنل تبدیل می‌کنه (a-z، 0-9 و _ ، بین ۳ تا ۳۲ کاراکتر)."""
    clean = re.sub(r"[^a-zA-Z0-9_]", "", (raw or "").strip().lower())
    if len(clean) < 3:
        clean = f"{fallback}{clean}"
    return clean[:32]


def random_suffix(k: int = 4) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=k))


class PasargadAPI:
    TOKEN_PATH = "/api/admin/token"
    USER_PATH = "/api/user"

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        sub_domain: str = "",
        verify_ssl: bool = False,
        timeout: int = 25,
        proxies: dict | None = None,
        inbounds: dict | None = None,
    ):
        self.base_url = (base_url or "").strip().rstrip("/")
        self.username = (username or "").strip()
        self.password = (password or "").strip()
        # اگه لینک سابسکرایب باید روی دامنه‌ی دیگه‌ای سرو بشه (مثلاً CDN)
        self.sub_domain = (sub_domain or "").strip().rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.proxies = proxies if proxies is not None else DEFAULT_PROXIES
        self.inbounds = inbounds if inbounds is not None else DEFAULT_INBOUNDS

        self.access_token: str | None = None
        self._token_expires_at: float = 0.0
        self._lock = asyncio.Lock()

    # ---------- helpers ----------
    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.username and self.password)

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _new_session(self) -> aiohttp.ClientSession:
        connector = aiohttp.TCPConnector(ssl=False) if not self.verify_ssl else None
        return aiohttp.ClientSession(timeout=self.timeout, connector=connector)

    # ---------- auth ----------
    async def get_token(self, force: bool = False) -> str:
        """گرفتن (و کش کردن) توکن احراز هویت پنل."""
        async with self._lock:
            if self.access_token and not force and time.time() < self._token_expires_at:
                return self.access_token

            if not self.configured:
                raise PanelError("اطلاعات پنل (آدرس/نام کاربری/رمز) کامل تنظیم نشده.")

            data = {
                "username": self.username,
                "password": self.password,
                "grant_type": "password",
            }
            try:
                async with self._new_session() as session:
                    async with session.post(self._url(self.TOKEN_PATH), data=data) as resp:
                        text = await resp.text()
                        if resp.status != 200:
                            raise PanelError(f"احراز هویت پنل ناموفق بود (کد {resp.status}): {text[:200]}")
                        try:
                            payload = json.loads(text)
                        except json.JSONDecodeError:
                            raise PanelError(f"پاسخ نامعتبر از پنل: {text[:200]}")
            except aiohttp.ClientError as e:
                raise PanelError(f"عدم دسترسی به پنل: {e}") from e
            except asyncio.TimeoutError as e:
                raise PanelError("زمان اتصال به پنل تمام شد (Timeout).") from e

            token = payload.get("access_token")
            if not token:
                raise PanelError(f"توکن در پاسخ پنل پیدا نشد: {str(payload)[:200]}")

            self.access_token = token
            # اکثر پنل‌ها expires_in نمی‌فرستن؛ محافظه‌کارانه ۵۰ دقیقه کش می‌کنیم
            expires_in = payload.get("expires_in") or 3000
            self._token_expires_at = time.time() + float(expires_in) - 60
            return token

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
        params: dict | None = None,
        allow_retry: bool = True,
    ) -> Any:
        token = await self.get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            async with self._new_session() as session:
                async with session.request(
                    method, self._url(path), json=json_body, params=params, headers=headers
                ) as resp:
                    text = await resp.text()

                    if resp.status == 401 and allow_retry:
                        # توکن منقضی شده -> یک‌بار دیگه لاگین می‌کنیم
                        await self.get_token(force=True)
                        return await self._request(
                            method, path, json_body=json_body, params=params, allow_retry=False
                        )

                    if 200 <= resp.status < 300:
                        if not text:
                            return {}
                        try:
                            return json.loads(text)
                        except json.JSONDecodeError:
                            return {"raw": text}

                    if resp.status == 404:
                        return None

                    raise PanelError(f"خطای پنل (کد {resp.status}): {_short_error(text)}")
        except aiohttp.ClientError as e:
            raise PanelError(f"عدم دسترسی به پنل: {e}") from e
        except asyncio.TimeoutError as e:
            raise PanelError("زمان پاسخ پنل تمام شد (Timeout).") from e

    # ---------- users ----------
    async def create_user(
        self,
        username: str,
        data_limit_gb: int = 0,
        expire_days: int = 0,
        *,
        note: str = "",
        proxies: dict | None = None,
        inbounds: dict | None = None,
        auto_rename: bool = True,
    ) -> dict:
        """
        ساخت کاربر جدید روی پنل.
        data_limit_gb = 0  یعنی حجم نامحدود
        expire_days   = 0  یعنی بدون تاریخ انقضا
        """
        username = sanitize_username(username)
        data_limit = int(data_limit_gb) * GB if data_limit_gb and int(data_limit_gb) > 0 else 0
        expire = int(time.time()) + int(expire_days) * 86400 if expire_days and int(expire_days) > 0 else 0

        payload = {
            "username": username,
            "proxies": proxies if proxies is not None else self.proxies,
            "inbounds": inbounds if inbounds is not None else self.inbounds,
            "data_limit": data_limit,
            "data_limit_reset_strategy": "no_reset",
            "expire": expire,
            "status": "active",
            "note": note,
        }

        try:
            result = await self._request("POST", self.USER_PATH, json_body=payload)
        except PanelError as e:
            # نام کاربری تکراری -> با پسوند تصادفی دوباره تلاش می‌کنیم
            msg = str(e).lower()
            if auto_rename and ("409" in msg or "exists" in msg or "duplicate" in msg):
                new_username = sanitize_username(f"{username[:26]}_{random_suffix(4)}")
                return await self.create_user(
                    new_username,
                    data_limit_gb,
                    expire_days,
                    note=note,
                    proxies=proxies,
                    inbounds=inbounds,
                    auto_rename=False,
                )
            raise

        if not result:
            raise PanelError("پنل پاسخ معتبری برای ساخت کاربر برنگرداند.")
        return result

    async def get_user(self, username: str) -> dict | None:
        return await self._request("GET", f"{self.USER_PATH}/{username}")

    async def modify_user(self, username: str, fields: dict) -> dict | None:
        return await self._request("PUT", f"{self.USER_PATH}/{username}", json_body=fields)

    async def delete_user(self, username: str) -> bool:
        await self._request("DELETE", f"{self.USER_PATH}/{username}")
        return True

    async def reset_usage(self, username: str) -> dict | None:
        return await self._request("POST", f"{self.USER_PATH}/{username}/reset")

    async def renew_user(self, username: str, add_days: int = 0, add_gb: int = 0) -> dict | None:
        """تمدید یک اکانت موجود: به تاریخ انقضا روز و به حجم، گیگ اضافه می‌کنه."""
        user = await self.get_user(username)
        if not user:
            raise PanelError("این اکانت روی پنل پیدا نشد.")

        fields: dict[str, Any] = {}

        if add_days and add_days > 0:
            now = int(time.time())
            current_expire = int(user.get("expire") or 0)
            base = current_expire if current_expire > now else now
            fields["expire"] = base + add_days * 86400

        if add_gb and add_gb > 0:
            current_limit = int(user.get("data_limit") or 0)
            if current_limit > 0:
                fields["data_limit"] = current_limit + add_gb * GB
            else:
                fields["data_limit"] = add_gb * GB

        fields["status"] = "active"
        return await self.modify_user(username, fields)

    # ---------- panel info ----------
    async def get_system_stats(self) -> dict | None:
        return await self._request("GET", "/api/system")

    async def get_inbounds(self) -> dict | None:
        return await self._request("GET", "/api/inbounds")

    async def test_connection(self) -> tuple[bool, str]:
        """تست اتصال: لاگین + خواندن اطلاعات سیستم. خروجی: (موفق؟، توضیح)"""
        try:
            await self.get_token(force=True)
        except PanelError as e:
            return False, str(e)

        try:
            stats = await self.get_system_stats()
        except PanelError as e:
            return True, f"لاگین موفق بود ولی خواندن اطلاعات سیستم خطا داد: {e}"

        if not stats:
            return True, "لاگین موفق بود (اند‌پوینت /api/system روی این پنل فعال نیست)."

        parts = []
        if stats.get("version"):
            parts.append(f"نسخه پنل: {stats['version']}")
        if stats.get("total_user") is not None:
            parts.append(f"تعداد کاربران: {stats['total_user']}")
        if stats.get("users_active") is not None:
            parts.append(f"کاربران فعال: {stats['users_active']}")
        return True, " | ".join(parts) if parts else "اتصال برقرار است."

    # ---------- output helpers ----------
    def subscription_link(self, user_info: dict) -> str:
        """لینک سابسکرایب رو از خروجی پنل درمیاره و در صورت نسبی بودن، کاملش می‌کنه."""
        sub = (user_info or {}).get("subscription_url") or ""
        if not sub:
            return ""
        if not sub.startswith("http"):
            sub = f"{self.base_url}{sub if sub.startswith('/') else '/' + sub}"
        if self.sub_domain:
            sub = re.sub(r"^https?://[^/]+", self.sub_domain, sub)
        return sub

    @staticmethod
    def config_links(user_info: dict, limit: int = 6) -> list[str]:
        links = (user_info or {}).get("links") or []
        return [str(x) for x in links[:limit]]

    @staticmethod
    def usage_report(user_info: dict) -> str:
        """خلاصه‌ی وضعیت مصرف یک اکانت به فارسی."""
        if not user_info:
            return "اطلاعاتی از پنل دریافت نشد."

        used = int(user_info.get("used_traffic") or 0)
        limit = int(user_info.get("data_limit") or 0)
        used_gb = used / GB
        if limit > 0:
            limit_gb = limit / GB
            remain_gb = max(limit_gb - used_gb, 0)
            traffic = f"{used_gb:.2f} از {limit_gb:.0f} گیگ (باقیمانده: {remain_gb:.2f} گیگ)"
        else:
            traffic = f"{used_gb:.2f} گیگ مصرف‌شده (حجم نامحدود)"

        expire = int(user_info.get("expire") or 0)
        if expire > 0:
            remain_days = int((expire - time.time()) // 86400)
            expiry = f"{remain_days} روز باقیمانده" if remain_days >= 0 else "منقضی شده"
        else:
            expiry = "بدون تاریخ انقضا"

        status_map = {
            "active": "🟢 فعال",
            "disabled": "⚪️ غیرفعال",
            "limited": "🔴 اتمام حجم",
            "expired": "🔴 منقضی شده",
            "on_hold": "🟡 در انتظار اولین اتصال",
        }
        status = status_map.get(str(user_info.get("status")), str(user_info.get("status") or "-"))

        return f"📶 وضعیت: {status}\n📊 مصرف: {traffic}\n⏳ اعتبار: {expiry}"


def _short_error(text: str) -> str:
    """پیام خطای پنل رو خلاصه و خوانا می‌کنه."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return (text or "")[:250]

    detail = data.get("detail", data) if isinstance(data, dict) else data
    if isinstance(detail, list):
        msgs = []
        for item in detail:
            if isinstance(item, dict):
                loc = ".".join(str(x) for x in item.get("loc", [])[1:])
                msgs.append(f"{loc}: {item.get('msg')}" if loc else str(item.get("msg")))
            else:
                msgs.append(str(item))
        return " ؛ ".join(msgs)[:250]
    return str(detail)[:250]


# ---------- کش کلاینت‌ها (برای اینکه توکن بین درخواست‌ها حفظ بشه) ----------
_clients: dict[tuple, "PasargadAPI"] = {}


def get_client(
    base_url: str,
    username: str,
    password: str,
    *,
    sub_domain: str = "",
    proxies: dict | None = None,
    inbounds: dict | None = None,
) -> PasargadAPI:
    """یک نمونه‌ی کش‌شده از کلاینت برمی‌گردونه تا توکن هر بار دوباره گرفته نشه."""
    key = (base_url, username, password, sub_domain, json.dumps(proxies, sort_keys=True) if proxies else "")
    client = _clients.get(key)
    if client is None:
        client = PasargadAPI(
            base_url, username, password, sub_domain=sub_domain, proxies=proxies, inbounds=inbounds
        )
        _clients[key] = client
    return client
