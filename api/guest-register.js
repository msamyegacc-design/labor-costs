'use strict';
const L = require('./_lib');
const crypto = require('crypto');

// تسجيل ضيف: يستلم الاسم والموبايل، وينشئ يوزر + باسورد تلقائي (تجربة 7 أيام) ويرجعهم للضيف.
module.exports = async (req, res) => {
  L.cors(res);
  if (req.method === 'OPTIONS') return L.send(res, 204, {});
  if (req.method !== 'POST') return L.send(res, 405, { error: 'method' });
  const b = await L.readBody(req);
  const name = L.cleanName(b.name), phone = L.cleanPhone(b.phone);
  if (name.length < 2) return L.send(res, 400, { error: 'اكتب اسمك' });
  if (!L.PHONE_RE.test(phone)) return L.send(res, 400, { error: 'اكتب رقم موبايل صحيح' });
  if (L.limited('r-ip:' + L.clientIp(req), 6, 3600e3)) return L.send(res, 429, { error: 'محاولات كثيرة — حاول بعد قليل' });
  try {
    if (await L.fsFind(L.GUEST_REG, 'phone', phone)) return L.send(res, 409, { error: 'هذا الرقم مسجّل كضيف من قبل — تواصل مع الإدارة' });
    const now = L._deps.now(), al = 'abcdefghjkmnpqrstuvwxyz23456789';
    let rec = null, pass = '';
    for (let i = 0; i < 8 && !rec; i++) {
      const username = 'guest' + String(crypto.randomInt(1000, 10000));
      pass = ''; for (let k = 0; k < 6; k++) pass += al[crypto.randomInt(al.length)];
      const r = {
        username, name, phone, pw: pass, passHash: L.hashPass(pass),
        createdAt: new Date(now).toISOString(), expiresAt: new Date(now + L.TRIAL_DAYS * 86400000).toISOString(),
        status: 'active', lastLogin: '', loginCount: 0, extendedCount: 0, lastNotifyAt: 0,
        deviceId: '', ip: L.clientIp(req), lastIp: '', ua: String(req.headers['user-agent'] || '').slice(0, 200)
      };
      if (await L.fsCreate(L.GUEST_REG, username, r)) rec = r;
    }
    if (!rec) return L.send(res, 500, { error: 'تعذّر إنشاء الحساب، حاول مرة أخرى' });
    await L.notifyAdmin('🆕 ضيف جديد: ' + name,
      '🆕 ضيف جديد سجّل في النسخة التجريبية\nالاسم: ' + name + '\nالموبايل: ' + phone + '\nاليوزر: ' + rec.username + '\nالباسورد: ' + pass +
      '\nIP: ' + (rec.ip || '-') + '\nالوقت: ' + L.cairo(now) + '\n\nرابط النظام: ' + L.APP_URL + '\n(ادخل بيوزرك ← الضيوف لإدارته)');
    const { passHash, pw, ...pub } = rec;
    L.send(res, 200, { ok: true, username: rec.username, password: pass, record: pub });
  } catch (e) { console.error('guest-register', e.message); L.send(res, 502, { error: 'تعذّر إنشاء الحساب — حاول بعد قليل' }); }
};
