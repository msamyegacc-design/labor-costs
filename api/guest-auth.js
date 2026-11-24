'use strict';
const L = require('./_lib');

// مسار احتياطي لتسجيل دخول الضيف عبر السيرفر إذا تعذّر اتصال المتصفح المباشر بـ Firestore
module.exports = async (req, res) => {
  L.cors(res);
  if (req.method === 'OPTIONS') return L.send(res, 204, {});
  if (req.method !== 'POST') return L.send(res, 405, { error: 'method' });
  const b = await L.readBody(req);
  const id = String(b.id || '').trim().toLowerCase().slice(0, 100), pass = String(b.password || '').slice(0, 64);
  if (!id || !pass) return L.send(res, 400, { error: 'bad' });
  if (L.limited('a-ip:' + L.clientIp(req), 40, 900e3) || L.limited('a-id:' + id, 10, 900e3)) return L.send(res, 429, { error: 'محاولات كثيرة — انتظر قليلاً' });
  try {
    const g = /^guest\d{3,}$/.test(id) ? await L.fsGet(L.GUEST_REG, id) : (id.includes('@') ? await L.fsFind(L.GUEST_REG, 'email', id) : null);
    if (!g || !L.checkPass(pass, g.passHash)) return L.send(res, 401, { error: 'invalid' });
    const { passHash, ...pub } = g;
    L.send(res, 200, { ok: true, record: pub });
  } catch (e) { console.error('guest-auth', e.message); L.send(res, 502, { error: 'fail' }); }
};
