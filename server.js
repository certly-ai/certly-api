// Certly API - v0.2.0 (single self-contained file for easy deploy)
// Stateless: no database, no personal data stored.
// v0.2.0 (2026-07-06):
//   - AUTH LAYER on /v1/certificates: RapidAPI proxy secret (x-rapidapi-proxy-secret)
//     OR partner key (x-api-key, comma-separated allowlist in API_KEYS env).
//     Enforcement only activates when RAPIDAPI_PROXY_SECRET or API_KEYS is set,
//     so deploys stay safe before the env vars land.
//   - FREE DEMO (lead magnet): POST /free/issue - no signup, watermarked SAMPLE
//     certificate + live verify page, per-IP and global daily rate limits,
//     CORS restricted to certlyapi.com.
//   - Verify page renders a SAMPLE banner for demo certificates.
const express = require('express');
const crypto = require('crypto');
const { PDFDocument, StandardFonts, rgb, degrees } = require('pdf-lib');
const QRCode = require('qrcode');

const app = express();
app.use(express.json({ limit: '1mb' }));
const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const SECRET = process.env.SIGNING_SECRET || 'dev-insecure-secret-change-me';

// ---------- auth (v0.2.0) ----------
const PROXY_SECRET = process.env.RAPIDAPI_PROXY_SECRET || '';
const API_KEYS = (process.env.API_KEYS || '').split(',').map(s => s.trim()).filter(Boolean);
const AUTH_ON = Boolean(PROXY_SECRET || API_KEYS.length);
function safeEq(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function requireAuth(req, res, next) {
  if (!AUTH_ON) return next(); // env not set yet -> open (pre-v0.2 behavior)
  const ps = req.headers['x-rapidapi-proxy-secret'];
  if (ps && PROXY_SECRET && safeEq(ps, PROXY_SECRET)) return next();
  const key = req.headers['x-api-key'];
  if (key && API_KEYS.some(k => safeEq(key, k))) return next();
  return res.status(401).json({ error: 'unauthorized', hint: 'Subscribe on RapidAPI (rapidapi.com/certlyapplive/api/certly-verifiable-certificates) or use your partner X-Api-Key.' });
}

// ---------- demo rate limiting (in-memory; resets on restart, fine for a free demo) ----------
const DEMO_PER_IP = parseInt(process.env.DEMO_PER_IP || '5', 10);      // per IP per UTC day
const DEMO_GLOBAL = parseInt(process.env.DEMO_GLOBAL || '300', 10);    // total per UTC day
const demoIp = new Map();
let demoGlobal = { day: '', count: 0 };
function demoAllowed(ip) {
  const day = new Date().toISOString().slice(0, 10);
  if (demoGlobal.day !== day) { demoGlobal = { day, count: 0 }; demoIp.clear(); }
  if (demoGlobal.count >= DEMO_GLOBAL) return false;
  const rec = demoIp.get(ip) || { count: 0 };
  if (rec.count >= DEMO_PER_IP) return false;
  rec.count += 1; demoIp.set(ip, rec); demoGlobal.count += 1;
  return true;
}
function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  return (typeof xf === 'string' && xf.split(',')[0].trim()) || req.socket.remoteAddress || 'unknown';
}

// ---------- CORS for the demo (site -> API) ----------
const DEMO_ORIGINS = ['https://certlyapi.com', 'https://www.certlyapi.com'];
function demoCors(req, res, next) {
  const origin = req.headers.origin;
  if (origin && DEMO_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
}

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
async function generateCertificatePDF({ name, title, date, issuer, verifyUrl, credentialId, sample }) {
  const pdf = await PDFDocument.create();
  const page = pdf.addPage([842, 595]);
  const { width, height } = page.getSize();
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const reg = await pdf.embedFont(StandardFonts.Helvetica);
  const ink = rgb(0.11, 0.13, 0.18), accent = rgb(0.31, 0.27, 0.9), muted = rgb(0.35, 0.38, 0.48);
  page.drawRectangle({ x: 26, y: 26, width: width - 52, height: height - 52, borderColor: accent, borderWidth: 2 });
  page.drawRectangle({ x: 34, y: 34, width: width - 68, height: height - 68, borderColor: rgb(0.85, 0.86, 0.95), borderWidth: 1 });
  if (sample) {
    // diagonal watermark, drawn before the text so content stays readable
    const wm = 'SAMPLE';
    const size = 130;
    const w = bold.widthOfTextAtSize(wm, size);
    page.drawText(wm, { x: (width - w * 0.72) / 2, y: 110, size, font: bold, color: rgb(0.93, 0.93, 0.97), rotate: degrees(30) });
  }
  const center = (t, f, s, y, c) => { const x = (width - f.widthOfTextAtSize(String(t == null ? '' : t), s)) / 2; page.drawText(String(t == null ? '' : t), { x, y, size: s, font: f, color: c }); };
  center('CERTIFICATE', bold, 32, height - 130, accent);
  center(title ? 'of Achievement' : 'of Completion', reg, 13, height - 158, muted);
  center('This certifies that', reg, 13, height - 220, muted);
  center(name || '-', bold, 30, height - 262, ink);
  center('has successfully completed', reg, 13, height - 312, muted);
  center(title || '-', bold, 18, height - 344, ink);
  center(`Date: ${date || ''}`, reg, 12, 150, muted);
  center(`Issued by: ${issuer || ''}`, reg, 12, 128, muted);
  if (sample) center('Demo certificate issued via certlyapi.com - not a real credential', reg, 9, 96, rgb(0.72, 0.45, 0.12));
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
  const sampleBanner = v.sample ? `<div style="background:#fff4e0;border:1px solid #f2d49b;border-radius:10px;padding:10px 14px;margin-bottom:14px;color:#8a5a12;font-size:13px;font-weight:600">SAMPLE - issued from the Certly live demo. Real certificates look identical, without the watermark.</div>` : '';
  const sampleCta = v.sample ? `<p style="margin-top:14px;font-size:13px"><a href="https://certlyapi.com" style="color:#4f45e6;font-weight:600">Issue real verifiable certificates via the API - free tier, no card &rarr;</a></p>` : '';
  return `${head}<title>Verified certificate</title><body style="font-family:system-ui,sans-serif;max-width:520px;margin:56px auto;padding:0 20px">${sampleBanner}<div style="border:1px solid #cfe8d9;background:#eef7f1;border-radius:14px;padding:24px;text-align:center"><div style="color:#12885a;font-weight:800;font-size:12px;letter-spacing:1.5px">&#10003; VERIFIED &amp; AUTHENTIC</div><h1 style="margin:14px 0 4px;color:#111725">${esc(v.name)}</h1><p style="color:#57607a;margin:0">${esc(v.title)}</p><hr style="border:none;border-top:1px solid #e7e9f2;margin:18px 0"><p style="color:#57607a;font-size:14px;margin:4px 0">Date: ${esc(v.date)}</p><p style="color:#57607a;font-size:14px;margin:4px 0">Issued by: ${esc(v.issuer)}</p><p style="color:#8891a6;font-size:12px;margin-top:16px">Verified by Certly</p></div>${sampleCta}</body>`;
}
app.get('/', (req, res) => res.json({ service: 'certly-api', version: '0.2.0', endpoints: ['POST /v1/certificates', 'GET /v1/verify/:id', 'POST /free/issue (demo)', 'GET /health'] }));
app.get('/health', (req, res) => res.json({ ok: true }));
app.post('/v1/certificates', requireAuth, async (req, res) => {
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
// ---------- free demo endpoint (v0.2.0) ----------
const CTRL_RE = new RegExp('[\\u0000-\\u001f\\u007f]', 'g');
app.options('/free/issue', demoCors);
app.post('/free/issue', demoCors, async (req, res) => {
  try {
    if (!demoAllowed(clientIp(req))) return res.status(429).json({ error: 'demo_limit_reached', hint: 'Demo is limited per day. The API free tier (5 certs/month, no card) has no such limit: certlyapi.com' });
    const b = req.body || {};
    const clean = (s, max) => String(s == null ? '' : s).replace(CTRL_RE, '').trim().slice(0, max);
    const name = clean(b.name, 60) || 'Alex Example';
    const title = clean(b.course || b.title, 80) || 'Certly Live Demo Course';
    const date = new Date().toISOString().slice(0, 10);
    const issuer = 'Certly Demo';
    const payload = { n: name, t: title, d: date, i: issuer, ts: new Date().toISOString(), s: 1 };
    const credentialId = signCredential(payload);
    const verifyUrl = `${BASE_URL}/v1/verify/${encodeURIComponent(credentialId)}`;
    const pdf = await generateCertificatePDF({ name, title, date, issuer, verifyUrl, credentialId, sample: true });
    res.json({ sample: true, credential_id: credentialId, verify_url: verifyUrl, pdf_base64: pdf.toString('base64') });
  } catch (e) { res.status(500).json({ error: 'render_failed' }); }
});
app.get('/v1/verify/:id', (req, res) => {
  const p = verifyCredential(req.params.id);
  const wantsJson = (req.headers.accept || '').includes('application/json');
  if (!p) return wantsJson ? res.status(404).json({ valid: false }) : res.status(404).send(verifyPageHTML(null));
  const out = { valid: true, name: p.n, title: p.t, date: p.d, issuer: p.i, issued_at: p.ts, sample: p.s === 1 };
  return wantsJson ? res.json(out) : res.send(verifyPageHTML(out));
});
app.listen(PORT, () => console.log(`certly-api v0.2.0 on ${PORT}`));
