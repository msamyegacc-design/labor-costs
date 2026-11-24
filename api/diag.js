'use strict';
// تشخيص مؤقت: يعرض سبب رفض Firestore (بدون أي أسرار). سيُحذف بعد الإصلاح.
const L = require('./_lib');
module.exports = async (req, res) => {
  L.cors(res);
  const out = {};
  for (const withRef of [true, false]) {
    try {
      const r = await fetch(`https://firestore.googleapis.com/v1/projects/elkhawaga-60a80/databases/(default)/documents:runQuery?key=${process.env.FS_API_KEY || 'AIzaSyAQxNvYseziOCJpp4BHnRyjeFXEFesZBZg'}`, {
        method: 'POST', headers: Object.assign({ 'content-type': 'application/json' }, withRef ? { referer: L.APP_URL } : {}),
        body: JSON.stringify({ structuredQuery: { from: [{ collectionId: '__guests_registry__' }], limit: 1 } })
      });
      out[withRef ? 'withReferer' : 'noReferer'] = { status: r.status, body: (await r.text()).replace(/\s+/g, ' ').slice(0, 1500) };
    } catch (e) { out[withRef ? 'withReferer' : 'noReferer'] = { error: String(e.message) }; }
  }
  L.send(res, 200, out);
};
