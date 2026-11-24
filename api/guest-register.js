'use strict';
const L = require('./_lib');
const crypto = require('crypto');

// تسجيل ضيف: يستلم الاسم والموبايل، وينشئ يوزر + باسورد تلقائي (تجربة 7 أيام) ويرجعهم للضيف.
module.exports = async (req, res) => {
  L.cors(res);
  if (req.method === 'OPTIONS') return L.send(res, 204, {});
  if (req.method !== 'POST') return L.send(res, 405, { error: 'method' });
  if (L.limited('r-ip:' + L.clientIp(req), 3, 86400e3)) return L.send(res, 429, { error: 'تم إنشاء عدد كافٍ من الحسابات التجريبية من هذا الجهاز اليوم — تواصل مع الإدارة: ' + (process.env.ADMIN_PHONE || '01119309346') });
  try {
    const now = L._deps.now(), al = 'abcdefghjkmnpqrstuvwxyz23456789';
    let rec = null, pass = '';
    for (let i = 0; i < 8 && !rec; i++) {
      const username = 'guest' + String(crypto.randomInt(1000, 10000));
      pass = ''; for (let k = 0; k < 6; k++) pass += al[crypto.randomInt(al.length)];
      const r = {
        username, name: 'ضيف ' + username, phone: '', pw: pass, passHash: L.hashPass(pass),
        createdAt: new Date(now).toISOString(), expiresAt: new Date(now + L.TRIAL_DAYS * 86400000).toISOString(),
        status: 'active', lastLogin: '', loginCount: 0, extendedCount: 0, lastNotifyAt: 0,
        deviceId: '', ip: L.clientIp(req), lastIp: '', ua: String(req.headers['user-agent'] || '').slice(0, 200)
      };
      if (await L.fsCreate(L.GUEST_REG, username, r)) rec = r;
    }
    if (!rec) return L.send(res, 500, { error: 'تعذّر إنشاء الحساب، حاول مرة أخرى' });
    await L.notifyAdmin('🆕 ضيف جديد: ' + rec.username,
      '🆕 ضيف جديد أنشأ حساباً تجريبياً\nاليوزر: ' + rec.username + '\nالباسورد: ' + pass +
      '\nIP: ' + (rec.ip || '-') + '\nالوقت: ' + L.cairo(now) + '\n\nرابط النظام: ' + L.APP_URL + '\n(ادخل بيوزرك ← الضيوف لإدارته)');
    const { passHash, pw, ...pub } = rec;
    L.send(res, 200, { ok: true, username: rec.username, password: pass, record: pub });
  } catch (e) { console.error('guest-register', e.message); L.send(res, 502, { error: 'تعذّر إنشاء الحساب — حاول بعد قليل' }); }
};
