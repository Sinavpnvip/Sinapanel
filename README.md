# APP Panel · Advanced Proxy Panel

پنل پروکسی پیشرفته برای Cloudflare Workers / Pages  
**Advanced Proxy Panel** — bilingual (فارسی + English)

## ویژگی‌ها

- VLESS + Trojan over WebSocket + TLS
- پنل وب دو زبانه با رمز عبور (پیش‌فرض: `123456`)
- مدیریت ساب‌لینک (نام، حجم، پورت، Path، پروتکل)
- پروکسی و Clean IP **مخصوص هر ساب** + دکمه مغزن
- مدیریت کاربران (حجم، انقضا، دستگاه، یادداشت، ریست ترافیک)
- Fragment، Warp، DoH
- ذخیره در Cloudflare KV

## نصب سریع (Workers)

1. در [Cloudflare Dashboard](https://dash.cloudflare.com) یک Worker بسازید.
2. یک **KV Namespace** بسازید و به Worker با نام `APP_KV` متصل کنید.
3. محتوای `worker.js` را در Worker قرار دهید و Deploy کنید.
4. (اختیاری) متغیرهای محیطی:
   - `PASSWORD` — رمز پنل
   - `UUID` — UUID ثابت
   - `TROJAN_PASS` — رمز Trojan
   - `PROXYIP` — Proxy IP پیش‌فرض

5. به آدرس زیر بروید:
   ```
   https://YOUR-WORKER.workers.dev/panel
   ```
   رمز پیش‌فرض: **123456**

## نصب با Wrangler

```bash
npm i -g wrangler
wrangler login
wrangler kv:namespace create APP_KV
# id را در wrangler.toml بگذارید
wrangler deploy
```

## استفاده

1. وارد پنل شوید (`/panel`)
2. یک **ساب‌لینک** بسازید (پورت، Path، Proxy، Clean IP، AdBlock و ...)
3. لینک ساب را کپی کنید و در کلاینت Import کنید
4. کاربران را با محدودیت حجم/دستگاه/انقضا اضافه کنید

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
| `/sub` یا `/sub/{id}` | لینک ساب‌سکریپشن |
| `/doh` | DNS over HTTPS |
| `/api/*` | API داخلی پنل |

## نکات

- بدون KV هم کار می‌کند (تنظیمات در حافظه موقت Worker می‌ماند و با هر Deploy ریست می‌شود). برای استفاده واقعی حتماً KV وصل کنید.
- ترافیک واقعی کاربران در این نسخه به‌صورت دقیق شمارش نمی‌شود (محدودیت Workers). فیلدها برای مدیریت دستی و آماده‌سازی آینده هستند.
- Fragment و بخشی از Routing سمت کلاینت اعمال می‌شوند.

## لایسنس

MIT
