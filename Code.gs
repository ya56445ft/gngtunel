/**
 * سرویس ساب‌اسکریپشن v2rayNG با Google Apps Script (Web App)
 *
 * خروجی: لیست لینک‌های کانفیگ (vless / vmess / trojan / ss) که به‌صورت Base64 
 * برگردانده می‌شود؛ فرمتی که v2rayNG برای Subscription می‌شناسد.
 */

// ===== تنظیمات =====
const TOKEN = 'یک-رمز-طولانی-و-تصادفی-بذار';   // بدون این توکن خروجی داده نمی‌شود

// کانفیگ‌های واقعی سرور خودت را اینجا بگذار (هر کدام یک آیتم)
const CONFIGS = [
  'vless://UUID-SERVER-1@your-domain.com:443?encryption=none&security=tls&sni=your-domain.com&fp=chrome&type=ws&host=your-domain.com&path=%2Fws#Server-1',
  // 'vmess://eyJ2IjoiMiIs...#Server-2',
  // 'trojan://PASSWORD@your-domain.com:443?security=tls&sni=your-domain.com&type=tcp#Server-3',
];

// ===== Web App =====
function doGet(e) {
  const p = (e && e.parameter) || {};

  if (p.token !== TOKEN) {
    return ContentService.createTextOutput('Forbidden')
      .setMimeType(ContentService.MimeType.TEXT);
  }

  const list = CONFIGS.map(s => String(s).trim()).filter(Boolean);
  const plain = list.join('\n');

  // ?format=plain  → برای تست در مرورگر (متن ساده)
  if (p.format === 'plain') {
    return ContentService.createTextOutput(plain)
      .setMimeType(ContentService.MimeType.TEXT);
  }

  // پیش‌فرض: Base64 مخصوص v2rayNG
  const encoded = Utilities.base64Encode(plain, Utilities.Charset.UTF_8);
  return ContentService.createTextOutput(encoded)
    .setMimeType(ContentService.MimeType.TEXT);
}

// ===== کمکی: ساخت لینک VLESS از پارامترها =====
function buildVless(o) {
  const q = [
    'encryption=none',
    'security=' + (o.security || 'tls'),
    'sni=' + encodeURIComponent(o.sni || o.host),
    'fp=' + (o.fp || 'chrome'),
    'type=' + (o.type || 'ws'),
    'host=' + encodeURIComponent(o.host),
    'path=' + encodeURIComponent(o.path || '/'),
  ].join('&');
  return 'vless://' + o.uuid + '@' + o.host + ':' + (o.port || 443) +
         '?' + q + '#' + encodeURIComponent(o.name || 'Server');
}
