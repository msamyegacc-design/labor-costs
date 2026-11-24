'use strict';
const L = require('./_lib');

// يُستدعى عند دخول ضيف: يرسل للمدير تفاصيل الدخول (بحد أقصى مرة كل 10 دقائق لكل ضيف لمنع الإزعاج)
module.exports = async (req, res) => {
  L.cors(res);
  if (req.method === 'OPTIONS') return L.send(res, 204, {});
  if (req.method !== 'POST') return L.send(res, 405, { error: 'method' });
  const b = await L.readBody(req);
  const u = String(b.username || '');
  if (!/^guest\d{3,}$/.test(u)) return L.send(res, 400, { error: 'bad' });
  if (L.limited('n-ip:' + L.clientIp(req), 30, 3600e3)) return L.send(res, 429, { error: 'limit' });
  try {
    const g = await L.fsGet(L.GUEST_REG, u);
    if (!g || g.status !== 'active' || new Date(g.expiresAt).getTime() <= L._deps.now()) return L.send(res, 200, { ok: true, skipped: 'inactive' });
    const now = L._deps.now();
    if (now - Number(g.lastNotifyAt || 0) < 10 * 60e3) return L.send(res, 200, { ok: true, skipped: 'throttled' });
    await L.fsPatch(L.GUEST_REG, u, { lastNotifyAt: now });
    const left = Math.max(0, Math.ceil((new Date(g.expiresAt).getTime() - now) / 86400000));
    const text = '👤 ضيف دخل النظام\n' +
      'الاسم: ' + (g.name || '-') + '\nالموبايل: ' + (g.phone || '-') + '\nالإيميل: ' + (g.email || '-') + '\nاليوزر: ' + u +
      '\nرقم الدخول: ' + ((g.loginCount || 0) || 1) + '\nمتبقي من التجربة: ' + left + ' يوم' +
      '\nIP: ' + (L.clientIp(req) || '-') + '\nالجهاز: ' + String(req.headers['user-agent'] || '-').slice(0, 80) + '\nالوقت: ' + L.cairo(now) +
      '\n\nرابط النظام: ' + L.APP_URL + '\n(ادخل بيوزرك ← الضيوف ← نشاط لمشاهدة ما فعله)';
    const r = await L.notifyAdmin('👤 دخول ضيف: ' + (g.name || u), text);
    L.send(res, 200, { ok: true, sent: r });
  } catch (e) { console.error('guest-notify', e.message); L.send(res, 502, { error: 'fail' }); }
};
