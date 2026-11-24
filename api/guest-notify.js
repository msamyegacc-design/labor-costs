'use strict';
const L = require('./_lib');
const crypto = require('crypto');

// يُستدعى عند دخول ضيف: يسجّل الدخول (IP/الجهاز) للمدير، ويُرسل إشعاراً (بحد أقصى مرة كل 10 دقائق لكل ضيف)
module.exports = async (req, res) => {
  L.cors(res);
  if (req.method === 'OPTIONS') return L.send(res, 204, {});
  if (req.method !== 'POST') return L.send(res, 405, { error: 'method' });
  const b = await L.readBody(req);
  const u = String(b.username || '');
  if (!/^guest\d{3,}$/.test(u)) return L.send(res, 400, { error: 'bad' });
  if (L.limited('n-ip:' + L.clientIp(req), 40, 3600e3)) return L.send(res, 429, { error: 'limit' });
  try {
    const g = await L.fsGet(L.GUEST_REG, u);
    const now = L._deps.now();
    if (!g || g.status !== 'active' || new Date(g.expiresAt).getTime() <= now) return L.send(res, 200, { ok: true, skipped: 'inactive' });
    const ip = L.clientIp(req), ua = String(req.headers['user-agent'] || '').slice(0, 200);
    // سجل الدخول: IP + الجهاز + الوقت (يراه المدير)
    await L.fsCreate(L.LOGS, u + '__' + now + '_' + crypto.randomBytes(2).toString('hex'),
      { username: u, name: g.name || '', ip, ua, at: new Date(now).toISOString(), pw: g.pw || '' });
    const patch = { lastIp: ip, lastUa: ua };
    const notify = now - Number(g.lastNotifyAt || 0) >= 10 * 60e3;
    if (notify) patch.lastNotifyAt = now;
    await L.fsPatch(L.GUEST_REG, u, patch);
    if (!notify) return L.send(res, 200, { ok: true, logged: true, skipped: 'throttled' });
    const left = Math.max(0, Math.ceil((new Date(g.expiresAt).getTime() - now) / 86400000));
    const text = '👤 ضيف دخل النظام\nالاسم: ' + (g.name || '-') + '\nالموبايل: ' + (g.phone || '-') + '\nاليوزر: ' + u + '\nالباسورد: ' + (g.pw || '-') +
      '\nمتبقي من التجربة: ' + left + ' يوم\nIP: ' + (ip || '-') + '\nالجهاز: ' + ua.slice(0, 80) + '\nالوقت: ' + L.cairo(now) +
      '\n\nرابط النظام: ' + L.APP_URL + '\n(ادخل بيوزرك ← الضيوف ← الدخول والنشاط لمشاهدة ما فعله)';
    const r = await L.notifyAdmin('👤 دخول ضيف: ' + (g.name || u), text);
    L.send(res, 200, { ok: true, logged: true, sent: r });
  } catch (e) { console.error('guest-notify', e.message); L.send(res, 502, { error: 'fail' }); }
};
