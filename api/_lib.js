'use strict';
// مكتبة مشتركة لدوال السيرفر (Vercel Serverless). الملفات التي تبدأ بـ _ لا تُنشر كمسارات.
const crypto = require('crypto');

const PROJECT = process.env.FS_PROJECT || 'elkhawaga-60a80';
const API_KEY = process.env.FS_API_KEY || 'AIzaSyAQxNvYseziOCJpp4BHnRyjeFXEFesZBZg'; // مفتاح الويب العام (نفس الموجود بالصفحة)
const FS_BASE = process.env.FIRESTORE_BASE || 'https://firestore.googleapis.com/v1';
const GUEST_REG = '__guests_registry__';
const APP_URL = process.env.APP_URL || 'https://laborcost.vercel.app/';
const TRIAL_DAYS = 7;
const OTP_TTL_MS = 10 * 60 * 1000;

// نقاط حقن للاختبار
const _deps = { fetch: (...a) => fetch(...a), sendMail: null, now: () => Date.now() };

function secret() {
  const s = process.env.OTP_SECRET || process.env.GMAIL_APP_PASSWORD || '';
  return s ? crypto.createHash('sha256').update('otp:' + s).digest() : null;
}
function b64u(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function unb64u(s) { return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'); }
function otpHmac(email, code, exp) {
  return b64u(crypto.createHmac('sha256', secret()).update(email + '|' + code + '|' + exp).digest());
}
function makeToken(email, code) {
  const exp = _deps.now() + OTP_TTL_MS;
  return b64u(JSON.stringify({ e: email, x: exp, h: otpHmac(email, code, exp) }));
}
function checkToken(token, email, code) {
  let p; try { p = JSON.parse(unb64u(token).toString('utf8')); } catch (e) { return 'bad'; }
  if (!p || p.e !== email || !p.x || !p.h) return 'bad';
  if (_deps.now() > p.x) return 'expired';
  const a = Buffer.from(p.h), b = Buffer.from(otpHmac(email, String(code), p.x));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return 'wrong';
  return 'ok';
}

// ── تجزئة كلمة المرور (نفس الصيغة في الصفحة: s1$salt$sha256hex(salt:pass)) ──
function hashPass(pass, salt) {
  salt = salt || crypto.randomBytes(8).toString('hex');
  return 's1$' + salt + '$' + crypto.createHash('sha256').update(salt + ':' + pass, 'utf8').digest('hex');
}
function checkPass(pass, stored) {
  stored = String(stored || '');
  if (stored.startsWith('s1$')) { const [, salt] = stored.split('$'); return hashPass(pass, salt) === stored; }
  try { return Buffer.from(String(pass), 'utf8').toString('base64') === stored; } catch (e) { return false; } // صيغة قديمة
}

// ── Firestore REST ──
function toFs(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'string') return { stringValue: v };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(toFs) } };
  return { mapValue: { fields: Object.fromEntries(Object.entries(v).map(([k, x]) => [k, toFs(x)])) } };
}
function fromFs(v) {
  if (!v) return null;
  if ('stringValue' in v) return v.stringValue;
  if ('integerValue' in v) return Number(v.integerValue);
  if ('doubleValue' in v) return v.doubleValue;
  if ('booleanValue' in v) return v.booleanValue;
  if ('nullValue' in v) return null;
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(fromFs);
  if ('mapValue' in v) return Object.fromEntries(Object.entries(v.mapValue.fields || {}).map(([k, x]) => [k, fromFs(x)]));
  return null;
}
const docsUrl = () => `${FS_BASE}/projects/${PROJECT}/databases/(default)/documents`;
const fieldsOf = o => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, toFs(v)]));
const objOf = d => Object.fromEntries(Object.entries((d && d.fields) || {}).map(([k, v]) => [k, fromFs(v)]));

async function fsGet(col, id) {
  const r = await _deps.fetch(`${docsUrl()}/${col}/${encodeURIComponent(id)}?key=${API_KEY}`);
  if (r.status === 404) return null;
  if (!r.ok) throw new Error('fs get ' + r.status);
  return objOf(await r.json());
}
async function fsFind(col, field, value) {
  const r = await _deps.fetch(`${docsUrl()}:runQuery?key=${API_KEY}`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ structuredQuery: { from: [{ collectionId: col }], limit: 1,
      where: { fieldFilter: { field: { fieldPath: field }, op: 'EQUAL', value: toFs(value) } } } })
  });
  if (!r.ok) throw new Error('fs query ' + r.status);
  const rows = await r.json();
  const hit = (rows || []).find(x => x.document);
  return hit ? objOf(hit.document) : null;
}
async function fsCreate(col, id, obj) { // true=تم، false=موجود مسبقاً
  const r = await _deps.fetch(`${docsUrl()}/${col}?documentId=${encodeURIComponent(id)}&key=${API_KEY}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ fields: fieldsOf(obj) })
  });
  if (r.status === 409) return false;
  if (!r.ok) throw new Error('fs create ' + r.status);
  return true;
}
async function fsPatch(col, id, obj) {
  const mask = Object.keys(obj).map(k => 'updateMask.fieldPaths=' + encodeURIComponent(k)).join('&');
  const r = await _deps.fetch(`${docsUrl()}/${col}/${encodeURIComponent(id)}?${mask}&key=${API_KEY}`, {
    method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ fields: fieldsOf(obj) })
  });
  if (!r.ok) throw new Error('fs patch ' + r.status);
}

// ── البريد والإشعارات ──
async function sendMail({ to, subject, text, html }) {
  if (_deps.sendMail) return _deps.sendMail({ to, subject, text, html });
  const user = process.env.GMAIL_USER, pass = process.env.GMAIL_APP_PASSWORD;
  if (!user || !pass) { const e = new Error('mail-not-configured'); e.code = 'NOMAIL'; throw e; }
  const nodemailer = require('nodemailer');
  const tr = nodemailer.createTransport({ service: 'gmail', auth: { user, pass } });
  return tr.sendMail({ from: `"نظام تكاليف العمالة" <${user}>`, to, subject, text, html });
}
const esc = s => String(s == null ? '' : s).replace(/[&<>"'`]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' }[c]));
const cairo = (ms) => new Date(ms || _deps.now()).toLocaleString('ar-EG', { timeZone: 'Africa/Cairo', hour12: true });

// يرسل للمدير: إيميل (دائماً، على ADMIN_EMAIL أو حساب Gmail المرسِل) + واتساب CallMeBot / SMS Twilio إن تم ضبط مفاتيحهم
async function notifyAdmin(subject, text) {
  const out = {};
  const adminMail = process.env.ADMIN_EMAIL || process.env.GMAIL_USER;
  if (adminMail) {
    try { await sendMail({ to: adminMail, subject, text, html: '<div dir="rtl" style="font-family:Tahoma,Arial;font-size:15px;line-height:1.9;white-space:pre-line">' + esc(text) + '</div>' }); out.email = true; }
    catch (e) { out.email = false; console.error('notify email', e.message); }
  }
  const phone = String(process.env.ADMIN_PHONE || '201119309346').replace(/\D/g, '');
  if (process.env.CALLMEBOT_KEY) {
    try {
      const r = await _deps.fetch(`https://api.callmebot.com/whatsapp.php?phone=${phone}&text=${encodeURIComponent(text)}&apikey=${encodeURIComponent(process.env.CALLMEBOT_KEY)}`);
      out.whatsapp = r.ok;
    } catch (e) { out.whatsapp = false; console.error('notify wa', e.message); }
  }
  if (process.env.TWILIO_SID && process.env.TWILIO_TOKEN && process.env.TWILIO_FROM) {
    try {
      const r = await _deps.fetch(`https://api.twilio.com/2010-04-01/Accounts/${process.env.TWILIO_SID}/Messages.json`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: 'Basic ' + Buffer.from(process.env.TWILIO_SID + ':' + process.env.TWILIO_TOKEN).toString('base64') },
        body: new URLSearchParams({ To: '+' + phone, From: process.env.TWILIO_FROM, Body: text }).toString()
      });
      out.sms = r.ok;
    } catch (e) { out.sms = false; console.error('notify sms', e.message); }
  }
  return out;
}

// ── مساعدات HTTP ──
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  res.setHeader('Cache-Control', 'no-store');
}
function send(res, code, obj) { res.statusCode = code; res.setHeader('content-type', 'application/json; charset=utf-8'); res.end(JSON.stringify(obj)); }
async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch (e) { return {}; } }
  const chunks = []; let n = 0;
  for await (const c of req) { n += c.length; if (n > 20000) break; chunks.push(c); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch (e) { return {}; }
}
function clientIp(req) { return String((req.headers['x-forwarded-for'] || '').split(',')[0] || (req.socket && req.socket.remoteAddress) || '').trim(); }

// تحديد معدّل بسيط داخل الذاكرة (best-effort؛ كل نسخة سيرفر لها عدّادها)
const _hits = new Map();
function limited(key, max, windowMs) {
  const now = _deps.now(), arr = (_hits.get(key) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) { _hits.set(key, arr); return true; }
  arr.push(now); _hits.set(key, arr);
  if (_hits.size > 5000) _hits.clear();
  return false;
}

const cleanName = s => String(s || '').replace(/[<>&"'`]/g, '').trim().slice(0, 40);
const cleanEmail = s => String(s || '').trim().toLowerCase().slice(0, 100);
const cleanPhone = s => String(s || '').replace(/[^\d+]/g, '').slice(0, 16);
const EMAIL_RE = /^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']{2,}$/;
const PHONE_RE = /^\+?\d{10,15}$/;

module.exports = { toFs, fromFs, _deps, secret, makeToken, checkToken, hashPass, checkPass, fsGet, fsFind, fsCreate, fsPatch, sendMail, notifyAdmin,
  esc, cairo, cors, send, readBody, clientIp, limited, cleanName, cleanEmail, cleanPhone, EMAIL_RE, PHONE_RE, GUEST_REG, APP_URL, TRIAL_DAYS, _hits };
