/**
 * رله‌ی HTTP با Google Apps Script
 *
 * کلاینت یک POST با JSON می‌فرستد:
 * {
 *   "key": "AUTH_KEY",
 *   "url": "https://example.com/path",
 *   "method": "GET",
 *   "headers": { "User-Agent": "..." },
 *   "body": "<base64 یا خالی>"
 * }
 *
 * پاسخ:
 * { "status": 200, "headers": {...}, "body": "<base64>" }
 */

const AUTH_KEY = 'یک-کلید-طولانی-و-تصادفی-بذار';

// هدرهایی که نباید ارسال شوند (گوگل خودش مدیریت می‌کند)
const SKIP_HEADERS = ['host', 'content-length', 'connection', 'accept-encoding', 'transfer-encoding'];

function doPost(e) {
  try {
    const req = JSON.parse(e.postData.contents);

    if (req.key !== AUTH_KEY) return out({ error: 'unauthorized' });
    if (!req.url || !/^https?:\/\//i.test(req.url)) return out({ error: 'bad url' });

    // جلوگیری از حلقه (رله به خودش)
    if (/script\.google(usercontent)?\.com/i.test(req.url)) return out({ error: 'loop' });

    const headers = {};
    Object.keys(req.headers || {}).forEach(k => {
      if (SKIP_HEADERS.indexOf(k.toLowerCase()) === -1) headers[k] = req.headers[k];
    });

    const opt = {
      method: (req.method || 'GET').toLowerCase(),
      headers: headers,
      muteHttpExceptions: true,
      followRedirects: true,
      validateHttpsCertificates: true,
    };

    if (req.body) {
      opt.payload = Utilities.base64Decode(req.body);
      if (!headers['Content-Type'] && !headers['content-type']) {
        opt.contentType = 'application/octet-stream';
      }
    }

    const res = UrlFetchApp.fetch(req.url, opt);

    return out({
      status: res.getResponseCode(),
      headers: res.getAllHeaders(),
      body: Utilities.base64Encode(res.getContent()),
    });
  } catch (err) {
    return out({ error: String(err) });
  }
}

// برای تست سریع در مرورگر
function doGet() {
  return out({ ok: true, msg: 'relay is running' });
}

function out(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
