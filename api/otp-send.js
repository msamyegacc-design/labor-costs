'use strict';
const L = require('./_lib');
const crypto = require('crypto');

// الخطوة 1: يستلم الاسم/الإيميل/الموبايل ويرسل كود تحقق (6 أرقام) على الإيميل. لا يُخزَّن الكود — يُرجَع توكن موقّع.
module.exports = async (req, res) => {
  L.cors(res);
  if (req.method === 'OPTIONS') return L.send(res, 204, {});
  if (req.method !== 'POST') return L.send(res, 405, { error: 'method' });
  if (!L.secret()) return L.send(res, 503, { error: 'خدمة التحقق غير مفعّلة بعد — تواصل مع الإدارة' });
  const b = await L.readBody(req);
  const name = L.cleanName(b.name), email = L.cleanEmail(b.email), phone = L.cleanPhone(b.phone);
  if (name.length < 2) return L.send(res, 400, { error: 'اكتب اسمك' });
  if (!L.EMAIL_RE.test(email)) return L.send(res, 400, { error: 'اكتب إيميل صحيح' });
  if (!L.PHONE_RE.test(phone)) return L.send(res, 400, { error: 'اكتب رقم موبايل صحيح' });
  if (L.limited('ip:' + L.clientIp(req), 12, 3600e3) || L.limited('em:' + email, 5, 3600e3) || L.limited('em1:' + email, 1, 45e3))
    return L.send(res, 429, { error: 'محاولات كثيرة — انتظر دقيقة ثم حاول مرة أخرى' });
  try {
    if (await L.fsFind(L.GUEST_REG, 'email', email)) return L.send(res, 409, { error: 'هذا الإيميل مسجّل كضيف من قبل' });
    if (await L.fsFind(L.GUEST_REG, 'phone', phone)) return L.send(res, 409, { error: 'هذا الرقم مسجّل كضيف من قبل' });
  } catch (e) { console.error('otp-send fs', e.message); return L.send(res, 502, { error: 'تعذّر الاتصال بقاعدة البيانات — حاول بعد قليل' }); }
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  try {
    await L.sendMail({
      to: email, subject: 'كود التحقق ' + code + ' — نظام تكاليف العمالة',
      text: 'مرحباً ' + name + '\nكود التحقق الخاص بك: ' + code + '\nصالح لمدة 10 دقائق. إذا لم تطلبه تجاهل هذه الرسالة.',
      html: '<div dir="rtl" style="font-family:Tahoma,Arial;font-size:16px;line-height:2"><p>مرحباً ' + L.esc(name) + ' 👋</p><p>كود التحقق الخاص بك للتجربة المجانية:</p>' +
        '<p style="font-size:34px;font-weight:bold;letter-spacing:8px;background:#f1f5f9;display:inline-block;padding:6px 20px;border-radius:10px;direction:ltr">' + code + '</p>' +
        '<p style="color:#64748b;font-size:13px">صالح لمدة 10 دقائق. إذا لم تطلبه تجاهل هذه الرسالة.</p></div>'
    });
  } catch (e) {
    console.error('otp-send mail', e.message);
    return L.send(res, e.code === 'NOMAIL' ? 503 : 502, { error: e.code === 'NOMAIL' ? 'خدمة البريد غير مفعّلة بعد — تواصل مع الإدارة' : 'تعذّر إرسال الإيميل — تأكد من العنوان وحاول مرة أخرى' });
  }
  L.send(res, 200, { ok: true, token: L.makeToken(email, code), ttl: 600 });
};
