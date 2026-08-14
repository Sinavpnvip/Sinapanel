# APP Panel · Advanced Proxy Panel (v1.2 — fixed)

پنل پروکسی پیشرفته برای Cloudflare Workers / Pages
**Advanced Proxy Panel** — bilingual (فارسی + English)

> این نسخه (v1.2) شامل رفع باگ و مشکلات امنیتی/عملکردی نسخه قبلی است. فهرست کامل تغییرات پایین صفحه.

## ویژگی‌ها

- VLESS + **Trojan واقعی** روی WebSocket + TLS (نه فقط لینک، خود پروتکل هم کار می‌کند)
- پنل وب دو زبانه، ورود امن با نشست امضاشده (HMAC) — رمز پیش‌فرض: `sfdns990`
- هر **کاربر UUID و رمز Trojan مخصوص به خودش** دارد و لینک شخصی جداگانه می‌گیرد (`/sub/u/{id}`)
- اتصال واقعی کاربران به محدودیت‌هایشان گره خورده: کاربر غیرفعال/منقضی/پر شده رد می‌شود
- **شمارش واقعی حجم مصرفی** به ازای هر کاربر و هر ساب (تب «مصرف» در پنل)
- مدیریت ساب‌لینک (نام، حجم، پورت، Path، پروتکل)
- پروکسی و Clean IP مخصوص هر ساب + دکمه مغزن
- محدودیت تلاش ورود (Rate limit) روی صفحه لاگین
- Fragment، Warp، DoH
- ذخیره در Cloudflare KV (به‌شدت توصیه‌شده — پایین را ببینید)

## نصب سریع (Workers)

1. در [Cloudflare Dashboard](https://dash.cloudflare.com) یک Worker بسازید.
2. یک **KV Namespace** بسازید و به Worker با نام `APP_KV` متصل کنید. **این بار KV صرفاً «توصیه‌شده» نیست — عملاً لازم است**، چون بدون آن نشست‌ها و آمار مصرف با ری‌استارت Worker از دست می‌روند (پایین‌تر توضیح داده شده).
3. محتوای `worker.js` را در Worker قرار دهید و Deploy کنید.
4. (اختیاری) متغیرهای محیطی:
   - `PASSWORD` — رمز پنل
   - `UUID` — UUID ثابت مدیر
   - `TROJAN_PASS` — رمز Trojan مدیر
   - `PROXYIP` — Proxy IP پیش‌فرض

5. به آدرس زیر بروید:
   ```
   https://YOUR-WORKER.workers.dev/panel
   ```
   رمز پیش‌فرض: **sfdns990** — حتماً بلافاصله از تب «تنظیمات» تغییرش بدید.

## نصب با Wrangler

```bash
npm i -g wrangler
wrangler login
wrangler kv:namespace create APP_KV
# id را در wrangler.toml بگذارید
wrangler deploy
```

## استفاده

1. وارد پنل شوید (`/panel`) و رمز پیش‌فرض را عوض کنید.
2. یک **ساب‌لینک** بسازید (پورت، Path، Proxy، Clean IP، AdBlock و ...) — این لینک اشتراکی/مدیر است.
3. کاربر بسازید؛ هر کاربر خودکار UUID و رمز Trojan مخصوص خودش می‌گیرد.
4. از لیست کاربران دکمه «کپی لینک» را بزنید — لینک شخصی همان کاربر است (`/sub/u/{id}`) و باید همون به کاربر داده بشه، نه لینک مدیر.
5. مصرف واقعی هر کاربر/ساب را از تب «مصرف» ببینید.

## کلاینت‌های پیشنهادی

| کلاینت | پلتفرم | لینک |
|--------|--------|------|
| v2rayNG | Android | [GitHub](https://github.com/2dust/v2rayNG) |
| v2rayN | Windows | [GitHub](https://github.com/2dust/v2rayN) |
| Hiddify | همه | [GitHub](https://github.com/hiddify/hiddify-app) |
| Sing-box | همه | [GitHub](https://github.com/SagerNet/sing-box) |
| Streisand | iOS | [App Store](https://apps.apple.com/app/streisand/id6450534064) |

## مسیرها

| مسیر | توضیح |
|------|--------|
| `/panel` | پنل مدیریت |
| `/sub` یا `/sub/{id}` | لینک ساب‌سکریپشن مدیر/اشتراکی |
| `/sub/u/{userId}` | لینک شخصی همان کاربر (UUID/رمز Trojan خودش) |
| `/doh` | DNS over HTTPS |
| `/api/*` | API داخلی پنل (نیازمند ورود) |

## نکات و محدودیت‌های شناخته‌شده (صادقانه)

- **بدون KV**: پنل کار می‌کند ولی همه‌چیز (تنظیمات، کاربران، ساب‌ها، نشست ورود، آمار مصرف) فقط در حافظه‌ی همان ایزوله‌ی در حال اجرای Worker می‌ماند و با هر Deploy یا ری‌استارت ایزوله از بین می‌رود. برای استفاده‌ی واقعی حتماً KV وصل کنید.
- **شمارش ترافیک**: به ازای هر اتصال، بایت‌های آپلود/دانلود شمرده و در پایان اتصال یک‌بار در KV ذخیره می‌شوند (نه هر بسته، تا هزینه/سرعت لطمه نخورد). چون Workers توزیع‌شده است و هم‌زمانی درخواست‌ها را یک پردازش مرکزی مدیریت نمی‌کند، شمارش **تقریبی و eventually-consistent** است، نه دقیق ۱۰۰٪ — برای مدیریت مصرف کافی است، برای صورت‌حساب دقیق مالی نه.
- **محدودیت تعداد دستگاه**: فیلد «حداکثر دستگاه» صرفاً اطلاعاتی/مدیریتی است؛ روی یک پلتفرم edge توزیع‌شده مثل Workers، شمارش قطعی اتصالات هم‌زمان یک کاربر در سطح جهانی از نظر فنی قابل‌اتکا نیست.
- Fragment و بخشی از Routing سمت کلاینت اعمال می‌شوند.

## تغییرات نسخه v1.2 نسبت به نسخه قبلی

- رفع باگ امنیتی: بدون KV، هر کوکی بلندتر از ۸ کاراکتر لاگین را معتبر می‌شمرد؛ حالا نشست‌ها با HMAC امضا و اعتبارسنجی می‌شوند.
- رفع باگ: بدون KV، UUID/تنظیمات هر درخواست از نو تصادفی تولید می‌شد (اتصال عملاً قطع می‌شد)؛ حالا در حافظه کش می‌شود.
- Trojan واقعاً پیاده‌سازی شد (قبلاً فقط لینکش ساخته می‌شد ولی به‌عنوان VLESS رد می‌شد).
- هر کاربر UUID/رمز Trojan اختصاصی گرفت؛ محدودیت حجم/انقضا/غیرفعال‌سازی واقعاً روی اتصال اعمال می‌شود (قبلاً فقط نمایشی بود).
- شمارش واقعی حجم مصرفی به ازای کاربر/ساب + تب «مصرف» در پنل.
- رفع باگ پارس IPv6 (پدینگ صفر ناقص).
- محافظت در برابر فریم متنی WebSocket که قبلاً کرش می‌کرد.
- Rate limit روی لاگین + مقایسه constant-time رمز.
- رمز پیش‌فرض عوض شد به `sfdns990`.
- جلوگیری از نوشتن غیرضروری در KV روی هر درخواست هنگام استفاده از متغیرهای محیطی.

## لایسنس

MIT


## v2 Reliability Fixes
- Added defensive KV/JSON handling.
- Added input normalization and validation helpers.
- API errors can now be returned as structured JSON.
- Frontend error handling can display the server error instead of a generic `Error`.
- Existing protocol implementation and legacy KV array format are preserved.
- `APP_KV` must be configured in Cloudflare Workers.


## v3 Performance / Stability
- Edge-local 5s caches for settings/users/subscriptions reduce KV reads on every connection.
- Credential index is cached and invalidated when users/settings change.
- WebSocket connection setup no longer reads the entire users list for every connection.
- Added authenticated Brain endpoint health testing with bounded concurrency and timeout.
- Brain is admin-managed: the build does not bundle a harvested public-proxy list.
- Brain results are ranked by availability and latency.
- The existing protocol implementation is preserved rather than replaced blindly.
