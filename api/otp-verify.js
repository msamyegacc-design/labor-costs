'use strict';
const L = require('./_lib');
const crypto = require('crypto');

// الخطوة 2: يتحقق من الكود ثم ينشئ حساب الضيف (7 أيام) في السجلّ العام ويُبلغ المدير.
module.exports = async (req, res) => {
  L.cors(res);
  if (req.method === 'OPTIONS') return L.send(res, 204, {});
  if (req.method !== 'POST') return L.send(res, 405, { error: 'method' });
  if (!L.secret()) return L.send(res, 503, { error: 'خدمة التحقق غير مفعّلة بعد' });
  const b = await L.readBody(req);
  const name = L.cleanName(b.name), email = L.cleanEmail(b.email), phone = L.cleanPhone(b.phone);
  const code = String(b.code || '').replace(/\D/g, '').slice(0, 6), pass = String(b.password || '');
  if (name.length < 2 || !L.EMAIL_RE.test(email) || !L.PHONE_RE.test(phone)) return L.send(res, 400, { error: 'بيانات غير صحيحة' });
  if (code.length !== 6) return L.send(res, 400, { error: 'اكتب الكود المكوّن من 6 أرقام' });
  if (pass.length < 6 || pass.length > 64) return L.send(res, 400, { error: 'كلمة المرور من 6 إلى 64 حرفاً' });
  if (L.limited('v:' + email, 8, 15 * 60e3)) return L.send(res, 429, { error: 'محاولات كثيرة — اطلب كوداً جديداً بعد قليل' });
  const chk = L.checkToken(String(b.token || ''), email, code);
  if (chk === 'expired') return L.send(res, 400, { error: 'انتهت صلاحية الكود — اطلب كوداً جديداً' });
  if (chk !== 'ok') return L.send(res, 400, { error: 'الكود غير صحيح' });
  try {
    if (await L.fsFind(L.GUEST_REG, 'email', email)) return L.send(res, 409, { error: 'هذا الإيميل مسجّل كضيف من قبل' });
    if (await L.fsFind(L.GUEST_REG, 'phone', phone)) return L.send(res, 409, { error: 'هذا الرقم مسجّل كضيف من قبل' });
    const now = L._deps.now();
    let rec = null;
    for (let i = 0; i < 8 && !rec; i++) {
      const username = 'guest' + String(crypto.randomInt(1000, 10000));
      const r = {
        username, name, email, phone, emailVerified: true, passHash: L.hashPass(pass),
        createdAt: new Date(now).toISOString(), expiresAt: new Date(now + L.TRIAL_DAYS * 86400000).toISOString(),
        status: 'active', lastLogin: '', loginCount: 0, extendedCount: 0, lastNotifyAt: 0,
        deviceId: '', ip: L.clientIp(req), ua: String(req.headers['user-agent'] || '').slice(0, 200)
      };
      if (await L.fsCreate(L.GUEST_REG, username, r)) rec = r;
    }
    if (!rec) return L.send(res, 500, { error: 'تعذّر إنشاء الحساب، حاول مرة أخرى' });
    const text = '🆕 ضيف جديد سجّل في النسخة التجريبية\n' +
      'الاسم: ' + name + '\nالموبايل: ' + phone + '\nالإيميل: ' + email + '\nاليوزر: ' + rec.username +
      '\nمدة التجربة: ' + L.TRIAL_DAYS + ' أيام\nIP: ' + (rec.ip || '-') + '\nالوقت: ' + L.cairo(now) +
      '\n\nرابط النظام: ' + L.APP_URL + '\n(ادخل بيوزرك ← الضيوف لإدارته)';
    await L.notifyAdmin('🆕 ضيف جديد: ' + name, text);
    const { passHash, ...pub } = rec;
    L.send(res, 200, { ok: true, username: rec.username, record: pub });
  } catch (e) {
    console.error('otp-verify', e.message);
    L.send(res, 502, { error: 'تعذّر إنشاء الحساب — حاول بعد قليل' });
  }
};
