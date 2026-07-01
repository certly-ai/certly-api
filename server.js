// Certly API - MVP v0.1 (single self-contained file for easy deploy)
// Stateless: no database, no personal data stored. Auth/keys/metering/billing
// are handled by RapidAPI in front of this service.
const express = require('express');
const crypto = require('crypto');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const QRCode = require('qrcode');

const app = express();
app.use(express.json({ limit: '1mb' }));
const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const SECRET = process.env.SIGNING_SECRET || 'dev-insecure-secret-change-me';

function signCredential(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}
function verifyCredential(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { return JSON.parse(Buffer.from(data, 'base64url').toString('utf8')); } catch (e) { return null; }
}
async function generateCertificatePDF({ name, title, date, issuer, verifyUrl, credentialId }) {
  const pdf = await PDFDocument.create();
  const page = pdf.addPage([842, 595]);
  const { width, height } = page.getSize();
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const reg = await pdf.embedFont(StandardFonts.Helvetica);
  const ink = rgb(0.11, 0.13, 0.18), accent = rgb(0.31, 0.27, 0.9), muted = rgb(0.35, 0.38, 0.48);
  page.drawRectangle({ x: 26, y: 26, width: width - 52, height: height - 52, borderColor: accent, borderWidth: 2 });
  page.drawRectangle({ x: 34, y: 34, width: width - 68, height: height - 68, borderColor: rgb(0.85, 0.86, 0.95), borderWidth: 1 });
  const center = (t, f, s, y, c) => { const x = (width - f.widthOfTextAtSize(String(t == null ? '' : t), s)) / 2; page.drawText(String(t == null ? '' : t), { x, y, size: s, font: f, color: c }); };
  center('CERTIFICATE', bold, 32, height - 130, accent);
  center(title ? 'of Achievement' : 'of Completion', reg, 13, height - 158, muted);
  center('This certifies that', reg, 13, height - 220, muted);
  center(name || '-', bold, 30, height - 262, ink);
  center('has successfully completed', reg, 13, height - 312, muted);
  center(title || '-', bold, 18, height - 344, ink);
  center(`Date: ${date || ''}`, reg, 12, 150, muted);
  center(`Issued by: ${issuer || ''}`, reg, 12, 128, muted);
  if (verifyUrl) {
    try {
      const qrBuf = await QRCode.toBuffer(verifyUrl, { type: 'png', margin: 0, width: 120 });
      const qr = await pdf.embedPng(qrBuf);
      page.drawImage(qr, { x: width - 150, y: 62, width: 84, height: 84 });
      page.drawText('Scan to verify', { x: width - 152, y: 50, size: 8, font: reg, color: muted });
    } catch (e) {}
  }
  if (credentialId) page.drawText(`ID: ${credentialId.slice(0, 18)}...`, { x: 66, y: 50, size: 8, font: reg, color: muted });
  return Buffer.from(await pdf.save());
}
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
function verifyPageHTML(v) {
  const head = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
  if (!v) return `${head}<title>Not valid</title><body style="font-family:system-ui,sans-serif;text-align:center;padding:60px 20px"><h1 style="color:#b3261e">Certificate not valid</h1><p style="color:#57607a">This certificate could not be verified.</p></body>`;
  return `${head}<title>Verified certificate</title><body style="font-family:system-ui,sans-serif;max-width:520px;margin:56px auto;padding:0 20px"><div style="border:1px solid #cfe8d9;background:#eef7f1;border-radius:14px;padding:24px;text-align:center"><div style="color:#12885a;font-weight:800;font-size:12px;letter-spacing:1.5px">&#10003; VERIFIED &amp; AUTHENTIC</div><h1 style="margin:14px 0 4px;color:#111725">${esc(v.name)}</h1><p style="color:#57607a;margin:0">${esc(v.title)}</p><hr style="border:none;border-top:1px solid #e7e9f2;margin:18px 0"><p style="color:#57607a;font-size:14px;margin:4px 0">Date: ${esc(v.date)}</p><p style="color:#57607a;font-size:14px;margin:4px 0">Issued by: ${esc(v.issuer)}</p><p style="color:#8891a6;font-size:12px;margin-top:16px">Verified by Certly</p></div></body>`;
}
app.get('/', (req, res) => res.json({ service: 'certly-api', version: '0.1.0', endpoints: ['POST /v1/certificates', 'GET /v1/verify/:id', 'GET /health'] }));
app.get('/health', (req, res) => res.json({ ok: true }));
app.post('/v1/certificates', async (req, res) => {
  try {
    const { data = {}, options = {} } = req.body || {};
    const name = data.name, title = data.title || data.course, date = data.date || '', issuer = data.issuer || '';
    if (!name || !title) return res.status(400).json({ error: 'data.name and data.title (or data.course) are required' });
    const payload = { n: name, t: title, d: date, i: issuer, ts: new Date().toISOString() };
    const credentialId = signCredential(payload);
    const verifyUrl = `${BASE_URL}/v1/verify/${encodeURIComponent(credentialId)}`;
    const pdf = await generateCertificatePDF({ name, title, date, issuer, verifyUrl, credentialId });
    res.json({ credential_id: credentialId, verify_url: verifyUrl, pdf_base64: pdf.toString('base64'), format: options.format || 'pdf' });
  } catch (e) { res.status(500).json({ error: 'render_failed' }); }
});
app.get('/v1/verify/:id', (req, res) => {
  const p = verifyCredential(req.params.id);
  const wantsJson = (req.headers.accept || '').includes('application/json');
  if (!p) return wantsJson ? res.status(404).json({ valid: false }) : res.status(404).send(verifyPageHTML(null));
  const out = { valid: true, name: p.n, title: p.t, date: p.d, issuer: p.i, issued_at: p.ts };
  return wantsJson ? res.json(out) : res.send(verifyPageHTML(out));
});
app.listen(PORT, () => console.log(`certly-api v0.1.0 on ${PORT}`));
