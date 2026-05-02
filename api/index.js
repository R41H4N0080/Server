// ╔══════════════════════════════════════════════════════════════════════════╗
// ║              PRIVATE VAULT — UNIFIED BACKEND  (api/index.js)            ║
// ║  Single serverless handler for Vercel + Express fallback on Replit       ║
// ╠══════════════════════════════════════════════════════════════════════════╣
// ║  ROUTES (all → /api/index via vercel.json rewrites)                     ║
// ║   GET  /api/config        → Firebase config + adminEmail (gated)        ║
// ║   GET  /api/watchdog      → Heartbeat / integrity signal                ║
// ║   GET  /api/health        → Public uptime probe                         ║
// ║   GET  /api/check         → Owner diagnostic (needs INTEGRITY_TOKEN)    ║
// ║   POST /api/uid_find      → FB UID finder proxy (key hidden)            ║
// ║   POST /api/totp          → Server-side TOTP code generator (2FA)       ║
// ║   POST /api/fb-live       → Facebook live-check proxy (graph API)       ║
// ║   POST /api/ai            → OpenAI / Gemini proxy (keys server-side)    ║
// ║   POST /api/imgbb         → ImgBB image upload proxy (key server-side)  ║
// ╠══════════════════════════════════════════════════════════════════════════╣
// ║  QUICK-EDIT CONFIG GUIDE                                                ║
// ║  ─────────────────────────────────────────────────────────────────────  ║
// ║  § 1  FIREBASE CONFIG     line ~50   FIREBASE_CFG object                ║
// ║  § 2  ALLOWED DOMAINS     line ~65   DEFAULT_ALLOWED array              ║
// ║  § 3  RATE LIMITER        line ~80   RATE_LIMIT_MAX constant            ║
// ║  § 4  UID FINDER KEYS     line ~90   UID_FINDER_URL / UID_FINDER_KEY    ║
// ║  § 5  TOTP ENDPOINT       line ~230  /api/totp handler                  ║
// ║  § 6  FB LIVE ENDPOINT    line ~270  /api/fb-live handler               ║
// ╠══════════════════════════════════════════════════════════════════════════╣
// ║  SECURITY MODEL                                                          ║
// ║   • /api/config is blocked unless integrity check passes AND the         ║
// ║     request comes from an allowed domain.  Attackers who copy the        ║
// ║     front-end can't boot the app — they can't get the Firebase cfg.      ║
// ║   • Error payloads are deliberately generic ("service_unavailable") so   ║
// ║     no enumeration info leaks to an attacker.                            ║
// ║   • Firebase Web SDK config is intentionally public — security comes     ║
// ║     from Realtime DB Rules, NOT from hiding API keys.                    ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// ─── 0) INTEGRITY MODULE (api/check.js) ─────────────────────────────────────
// Loaded defensively — if check.js itself is missing/corrupt the
// site is treated as tampered and config is refused.
let _checkMod = null;
let _checkLoadError = null;
try {
  _checkMod = require('./check.js');
  if (!_checkMod || typeof _checkMod.check !== 'function') {
    _checkLoadError = 'check_module_invalid';
    _checkMod = null;
  }
} catch (e) {
  _checkLoadError = 'check_module_missing';
  _checkMod = null;
}

// ═══════════════════════════════════════════════════════════════════════════
// § 1  FIREBASE CONFIG
//      Override any field via environment variable (set in Vercel dashboard
//      or Replit Secrets).  The values below are the live project defaults.
//      To switch Firebase projects: update all fields + FIREBASE_DATABASE_URL.
// ═══════════════════════════════════════════════════════════════════════════
const FIREBASE_CFG = {
  apiKey:            process.env.FIREBASE_API_KEY             || "AIzaSyC7yPDkyFkNmMT0VHAe3c6CbFwNp7HSmEc",
  authDomain:        process.env.FIREBASE_AUTH_DOMAIN         || "accounts-store-4123a.firebaseapp.com",
  projectId:         process.env.FIREBASE_PROJECT_ID          || "accounts-store-4123a",
  storageBucket:     process.env.FIREBASE_STORAGE_BUCKET      || "accounts-store-4123a.firebasestorage.app",
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || "964244658201",
  appId:             process.env.FIREBASE_APP_ID              || "1:964244658201:web:2dd3b5ad001b4058057288",
  databaseURL:       process.env.FIREBASE_DATABASE_URL        || "https://accounts-store-4123a-default-rtdb.firebaseio.com"
};

// ═══════════════════════════════════════════════════════════════════════════
// § 1b  ADMIN + AI + IMGBB CONFIG  (set via Replit Secrets / Vercel env)
//   ADMIN_EMAIL    → admin Firebase login; default: admin@vaultadmin.local
//   OPENAI_API_KEY → OpenAI secret key for /api/ai proxy
//   GEMINI_API_KEY → Google Gemini key for /api/ai proxy
//   IMGBB_API_KEY  → ImgBB key for /api/imgbb image-upload proxy
// ═══════════════════════════════════════════════════════════════════════════
const ADMIN_EMAIL    = process.env.ADMIN_EMAIL    || "admin@vaultadmin.local";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";
const IMGBB_API_KEY  = process.env.IMGBB_API_KEY  || "";

// ═══════════════════════════════════════════════════════════════════════════
// § 2  ALLOWED DOMAINS
//      Requests from domains NOT in this list are rejected (403/503).
//      Rules:
//        • Leading dot  →  wildcard subdomain  e.g. ".replit.dev" matches
//          "anything.replit.dev"
//        • Empty array  →  allow ALL hosts (open mode, not recommended)
//        • Override entirely: set ALLOWED_DOMAINS env var (comma-separated)
//          e.g.  ALLOWED_DOMAINS=myvault.com,.myvault.app
// ═══════════════════════════════════════════════════════════════════════════
const DEFAULT_ALLOWED = [
  "account-store-eight.vercel.app",  // ← your Vercel production domain
  ".vercel.app",                     // all Vercel preview/deployment domains
  ".replit.dev",                     // Replit dev previews
  ".replit.app",                     // Replit published apps
  ".repl.co",                        // legacy Replit domain
  "localhost",                       // local dev
  "0.0.0.0",                         // local dev (all interfaces)
  "127.0.0.1"                        // local loopback
];
const ALLOWED_DOMAINS = (process.env.ALLOWED_DOMAINS || "")
  .split(",").map(s => s.trim()).filter(Boolean);
const HOST_ALLOWLIST = ALLOWED_DOMAINS.length ? ALLOWED_DOMAINS : DEFAULT_ALLOWED;

// ═══════════════════════════════════════════════════════════════════════════
// § 3  RATE LIMITER
//      60 requests / minute per (IP, route).  Increase RATE_LIMIT_MAX
//      if your app gets rate-limited during normal use.
//      Override: set  RATE_LIMIT_MAX=120  in env vars.
// ═══════════════════════════════════════════════════════════════════════════
const RATE_LIMIT_MAX    = parseInt(process.env.RATE_LIMIT_MAX || "60", 10);
const RATE_LIMIT_WINDOW = 60 * 1000;
const _rateBuckets = new Map();
function rateLimitHit(key) {
  const now = Date.now();
  const bucket = _rateBuckets.get(key);
  if (!bucket || now - bucket.start > RATE_LIMIT_WINDOW) {
    _rateBuckets.set(key, { start: now, count: 1 });
    return { ok: true, remaining: RATE_LIMIT_MAX - 1, resetIn: RATE_LIMIT_WINDOW };
  }
  bucket.count++;
  if (_rateBuckets.size > 5000) {
    for (const [k, v] of _rateBuckets) {
      if (now - v.start > RATE_LIMIT_WINDOW) _rateBuckets.delete(k);
    }
  }
  return {
    ok: bucket.count <= RATE_LIMIT_MAX,
    remaining: Math.max(0, RATE_LIMIT_MAX - bucket.count),
    resetIn: RATE_LIMIT_WINDOW - (now - bucket.start)
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// § 4  UID FINDER PROXY CONFIG
//      API key stays server-side and is never exposed to the browser.
//      Override with environment variables for security.
//        UID_FINDER_URL  — upstream API endpoint
//        UID_FINDER_KEY  — secret API key for the upstream service
// ═══════════════════════════════════════════════════════════════════════════
const UID_FINDER_URL = process.env.UID_FINDER_URL || "https://fb-uid-finder.vercel.app/api/uid_find";
const UID_FINDER_KEY = process.env.UID_FINDER_KEY || "my_secret_key_123";

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function getRequestHost(req) {
  const fwd = req.headers["x-forwarded-host"] || req.headers.host || "";
  let host = String(fwd).split(",")[0].split(":")[0].toLowerCase();
  if (host) return host;
  const origin = req.headers.origin || req.headers.referer || "";
  if (origin) {
    try { return new URL(origin).hostname.toLowerCase(); } catch (_) {}
  }
  return "";
}

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return (req.socket && req.socket.remoteAddress) || "unknown";
}

function isHostAllowed(host) {
  if (!HOST_ALLOWLIST.length) return true;
  if (HOST_ALLOWLIST.includes("*")) return true;
  if (!host) return false;
  return HOST_ALLOWLIST.some(d => {
    d = String(d).toLowerCase();
    if (d.startsWith(".")) return host === d.slice(1) || host.endsWith(d);
    return host === d;
  });
}

function setSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
}

function sendJSON(res, status, data) {
  res.statusCode = status;
  setSecurityHeaders(res);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(data));
}

function detectRoute(req) {
  const raw = req.url || "/";
  const qIdx = raw.indexOf("?");
  const pathname = qIdx >= 0 ? raw.slice(0, qIdx) : raw;
  const query    = qIdx >= 0 ? raw.slice(qIdx + 1) : "";

  // 1) explicit ?route=xxx (set by vercel.json rewrites)
  const m = query.match(/(?:^|&)route=([^&]+)/);
  if (m) return decodeURIComponent(m[1]).toLowerCase();

  // 2) req.query if the platform parsed it
  if (req.query && req.query.route) return String(req.query.route).toLowerCase();

  // 3) fall back to the path itself
  if (pathname.endsWith("/config"))        return "config";
  if (pathname.endsWith("/watchdog"))      return "watchdog";
  if (pathname.endsWith("/health"))        return "health";
  if (pathname.endsWith("/check"))         return "check";
  if (pathname.endsWith("/uid_find"))      return "uid_find";
  if (pathname.endsWith("/totp"))          return "totp";
  if (pathname.endsWith("/fb-live"))       return "fb-live";
  if (pathname.endsWith("/ai"))            return "ai";
  if (pathname.endsWith("/imgbb"))         return "imgbb";

  // 4) last-resort: original URL forwarded by some proxies
  const orig = req.headers["x-vercel-original-pathname"] || req.headers["x-forwarded-uri"] || "";
  if (orig.endsWith("/config"))        return "config";
  if (orig.endsWith("/watchdog"))      return "watchdog";
  if (orig.endsWith("/health"))        return "health";
  if (orig.endsWith("/check"))         return "check";
  if (orig.endsWith("/uid_find"))      return "uid_find";
  if (orig.endsWith("/totp"))          return "totp";
  if (orig.endsWith("/fb-live"))       return "fb-live";
  if (orig.endsWith("/ai"))            return "ai";
  if (orig.endsWith("/imgbb"))         return "imgbb";

  return "";
}

// Read raw POST body (Vercel doesn't pre-parse body by default)
function readBody(req) {
  return new Promise((resolve) => {
    if (req.body) {
      if (typeof req.body === "object") {
        const qs = require("querystring");
        return resolve(qs.stringify(req.body));
      }
      return resolve(String(req.body));
    }
    let raw = "";
    req.on("data", c => { raw += c; });
    req.on("end",  () => resolve(raw));
    req.on("error",() => resolve(""));
  });
}

// Parse body as JSON or urlencoded, return plain object
async function parseBody(req) {
  const raw = await readBody(req);
  if (!raw) return {};
  const ct = (req.headers["content-type"] || "").toLowerCase();
  if (ct.includes("application/json")) {
    try { return JSON.parse(raw); } catch (_) { return {}; }
  }
  const qs = require("querystring");
  return qs.parse(raw);
}

// ─── GENERIC HTTPS POST HELPER ───────────────────────────────────────────────
// Used by AI and ImgBB proxy routes.  Returns { status, body } or throws.
function httpsPost(hostname, path, headers, bodyStr) {
  return new Promise((resolve, reject) => {
    const https = require("https");
    const buf   = Buffer.from(bodyStr, "utf8");
    const opts  = {
      hostname,
      path,
      method:  "POST",
      headers: { ...headers, "Content-Length": buf.length },
      timeout: 30000
    };
    const req = https.request(opts, (res) => {
      let data = "";
      res.on("data", c => { data += c; });
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("upstream_timeout")); });
    req.on("error",   reject);
    req.write(bodyStr);
    req.end();
  });
}

// ─── UID FINDER PROXY ────────────────────────────────────────────────────────
function proxyUIDFind(link) {
  return new Promise((resolve, reject) => {
    const https = require("https");
    const qs    = require("querystring");
    const body  = qs.stringify({ link });
    const u     = new URL(UID_FINDER_URL);

    const opts = {
      hostname: u.hostname,
      path:     u.pathname + u.search,
      method:   "POST",
      headers: {
        "Content-Type":   "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
        "x-api-key":      UID_FINDER_KEY
      },
      timeout: 20000
    };

    const req = https.request(opts, (res) => {
      let data = "";
      res.on("data", c => { data += c; });
      res.on("end", () => {
        try {
          const json = JSON.parse(data);
          if (json.success === false) return reject(new Error(json.error || "upstream_error"));
          const d   = json.data || json;
          if (d.error && !d.id) return reject(new Error("rate_limited"));
          const uid  = String(d.id  || d.uid  || "").trim();
          const name = String(d.name || d.username || "").trim();
          if (!uid) return reject(new Error("uid_not_found"));
          resolve({ uid, name, link: d.link || link });
        } catch (e) { reject(new Error("parse_error")); }
      });
    });

    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    req.on("error",   e  => reject(e));
    req.write(body);
    req.end();
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// § 5  TOTP — SERVER-SIDE 2FA CODE GENERATOR
//      POST /api/totp  body: { secret: "BASE32SECRET", timestamp?: number }
//      Returns: { ok, code, remaining, expiresAt }
//      Uses Node.js built-in crypto (HMAC-SHA1) — no extra packages needed.
// ═══════════════════════════════════════════════════════════════════════════
function base32Decode(s) {
  const CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const str = s.toUpperCase().replace(/\s|=/g, "");
  let bits = "";
  for (const c of str) {
    const idx = CHARS.indexOf(c);
    if (idx < 0) continue;
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = Buffer.alloc(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}

function serverTOTP(secret, ts) {
  const crypto  = require("crypto");
  const now     = ts || Date.now();
  const counter = Math.floor(now / 1000 / 30);
  const keyBuf  = base32Decode(secret);

  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);

  const hmac   = crypto.createHmac("sha1", keyBuf);
  hmac.update(counterBuf);
  const hash   = hmac.digest();

  const offset = hash[hash.length - 1] & 0x0f;
  const code   = (
    ((hash[offset]     & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) <<  8) |
     (hash[offset + 3] & 0xff)
  );

  const remaining = 30 - (Math.floor(now / 1000) % 30);
  return {
    code:      String(code % 1000000).padStart(6, "0"),
    remaining,
    expiresAt: now + remaining * 1000
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// § 6  FB LIVE CHECK — FACEBOOK GRAPH API PROXY
//      POST /api/fb-live  body: { uid: "numericUIDorUsername" }
//      Returns: { ok, live: true|false|null, uid }
//      null = network/unknown error, false = account dead, true = account live
//      Proxying avoids browser CORS issues with graph.facebook.com.
// ═══════════════════════════════════════════════════════════════════════════
function checkFBLive(uid) {
  return new Promise((resolve) => {
    const https = require("https");
    const safeUID = encodeURIComponent(String(uid).trim());
    const opts = {
      hostname: "graph.facebook.com",
      path:     `/${safeUID}/picture?redirect=false`,
      method:   "GET",
      headers:  { "User-Agent": "Mozilla/5.0 (compatible; PrivateVaultBot/1.0)" },
      timeout:  15000
    };

    const req = https.request(opts, (res) => {
      let data = "";
      res.on("data", c => { data += c; });
      res.on("end", () => {
        if (res.statusCode !== 200) return resolve(false);
        try {
          const json = JSON.parse(data);
          resolve(!!(json && json.data && json.data.height));
        } catch (_) { resolve(null); }
      });
    });

    req.on("timeout", () => { req.destroy(); resolve(null); });
    req.on("error",   () => resolve(null));
    req.end();
  });
}

// ─── MAIN HANDLER ─────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  try {
    const route   = detectRoute(req);
    const host    = getRequestHost(req);
    const allowed = isHostAllowed(host);
    const method  = (req.method || "GET").toUpperCase();
    const ip      = getClientIp(req);

    // CORS headers (echo origin only when allowed)
    const origin = req.headers.origin;
    if (allowed && origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type");
      res.setHeader("Vary", "Origin");
    }

    // Pre-flight
    if (method === "OPTIONS") {
      setSecurityHeaders(res);
      res.statusCode = 204;
      return res.end();
    }

    // ── POST-only routes ────────────────────────────────────────────────────

    // uid_find — proxy FB UID finder (key hidden server-side)
    if (route === "uid_find") {
      if (!allowed) return sendJSON(res, 403, { ok: false, error: "domain_not_allowed" });
      if (method !== "POST") {
        res.setHeader("Allow", "POST, OPTIONS");
        return sendJSON(res, 405, { ok: false, error: "method_not_allowed" });
      }
      const rlUid = rateLimitHit(`${ip}:uid_find`);
      res.setHeader("X-RateLimit-Limit",     String(RATE_LIMIT_MAX));
      res.setHeader("X-RateLimit-Remaining", String(rlUid.remaining));
      if (!rlUid.ok) {
        res.setHeader("Retry-After", String(Math.ceil(rlUid.resetIn / 1000)));
        return sendJSON(res, 429, { ok: false, error: "rate_limited" });
      }
      try {
        const rawBody = await readBody(req);
        const qs      = require("querystring");
        const params  = qs.parse(rawBody);
        const link    = (params.link || "").trim();
        if (!link) return sendJSON(res, 400, { ok: false, error: "link_required" });
        const result  = await proxyUIDFind(link);
        return sendJSON(res, 200, { ok: true, uid: result.uid, name: result.name, link: result.link });
      } catch (e) {
        return sendJSON(res, 502, { ok: false, error: (e && e.message) || "uid_fetch_failed" });
      }
    }

    // § 5  totp — generate a TOTP code server-side (2FA)
    if (route === "totp") {
      if (!allowed) return sendJSON(res, 403, { ok: false, error: "domain_not_allowed" });
      if (method !== "POST") {
        res.setHeader("Allow", "POST, OPTIONS");
        return sendJSON(res, 405, { ok: false, error: "method_not_allowed" });
      }
      const rlTotp = rateLimitHit(`${ip}:totp`);
      res.setHeader("X-RateLimit-Limit",     String(RATE_LIMIT_MAX));
      res.setHeader("X-RateLimit-Remaining", String(rlTotp.remaining));
      if (!rlTotp.ok) {
        res.setHeader("Retry-After", String(Math.ceil(rlTotp.resetIn / 1000)));
        return sendJSON(res, 429, { ok: false, error: "rate_limited" });
      }
      try {
        const body   = await parseBody(req);
        const secret = (body.secret || "").toString().trim().replace(/\s/g, "");
        if (!secret) return sendJSON(res, 400, { ok: false, error: "secret_required" });
        const ts = body.timestamp ? parseInt(body.timestamp, 10) : undefined;
        const result = serverTOTP(secret, ts);
        return sendJSON(res, 200, { ok: true, ...result });
      } catch (e) {
        return sendJSON(res, 400, { ok: false, error: "invalid_secret", detail: String(e && e.message || e) });
      }
    }

    // § 6  fb-live — proxy Facebook graph API live check
    if (route === "fb-live") {
      if (!allowed) return sendJSON(res, 403, { ok: false, error: "domain_not_allowed" });
      if (method !== "POST") {
        res.setHeader("Allow", "POST, OPTIONS");
        return sendJSON(res, 405, { ok: false, error: "method_not_allowed" });
      }
      const rlFb = rateLimitHit(`${ip}:fb-live`);
      res.setHeader("X-RateLimit-Limit",     String(RATE_LIMIT_MAX));
      res.setHeader("X-RateLimit-Remaining", String(rlFb.remaining));
      if (!rlFb.ok) {
        res.setHeader("Retry-After", String(Math.ceil(rlFb.resetIn / 1000)));
        return sendJSON(res, 429, { ok: false, error: "rate_limited" });
      }
      try {
        const body = await parseBody(req);
        const uid  = (body.uid || "").toString().trim();
        if (!uid) return sendJSON(res, 400, { ok: false, error: "uid_required" });
        const live = await checkFBLive(uid);
        return sendJSON(res, 200, { ok: true, live, uid });
      } catch (e) {
        return sendJSON(res, 502, { ok: false, error: "fb_check_failed", detail: String(e && e.message || e) });
      }
    }

    // § 7  ai — proxy OpenAI or Gemini (API keys stay server-side)
    if (route === "ai") {
      if (!allowed) return sendJSON(res, 403, { ok: false, error: "domain_not_allowed" });
      if (method !== "POST") {
        res.setHeader("Allow", "POST, OPTIONS");
        return sendJSON(res, 405, { ok: false, error: "method_not_allowed" });
      }
      const rlAi = rateLimitHit(`${ip}:ai`);
      res.setHeader("X-RateLimit-Limit",     String(RATE_LIMIT_MAX));
      res.setHeader("X-RateLimit-Remaining", String(rlAi.remaining));
      if (!rlAi.ok) {
        res.setHeader("Retry-After", String(Math.ceil(rlAi.resetIn / 1000)));
        return sendJSON(res, 429, { ok: false, error: "rate_limited" });
      }
      try {
        const body     = await parseBody(req);
        const provider = String(body.provider || "openai").toLowerCase();
        const mode     = String(body.mode     || "chat").toLowerCase();
        const messages = Array.isArray(body.messages) ? body.messages : [];

        const systemPrompts = {
          chat:    "You are Private Vault AI, a helpful assistant for account security and management.",
          parse:   `You are a data parser. Extract account info from user text and return ONLY a JSON object with these fields if found: platform, name, uid, email, number, password, dob, note, status, recoveryKey. If you cannot parse, return {"error":"Could not parse account info"}. Return ONLY raw JSON, no markdown.`,
          analyze: "You are a security analyst. Analyze the given account information and provide a security assessment, risk level, and recommendations."
        };
        const systemText = systemPrompts[mode] || systemPrompts.chat;

        // Key priority: env var (server-side secret) → key sent from frontend (Firebase-stored)
        if (provider === "gemini") {
          const geminiKey = GEMINI_API_KEY || String(body.key || "").trim();
          if (!geminiKey) return sendJSON(res, 503, { ok: false, error: "Gemini API key not set. Please add it in Settings → AI Support → Google Gemini." });
          const contents = messages.map(m => ({
            role:  m.role === "assistant" ? "model" : "user",
            parts: [{ text: String(m.content || "") }]
          }));
          const payload = JSON.stringify({
            system_instruction: { parts: [{ text: systemText }] },
            contents,
            generationConfig: { maxOutputTokens: 600, temperature: 0.7 }
          });
          const r = await httpsPost(
            "generativelanguage.googleapis.com",
            `/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(geminiKey)}`,
            { "Content-Type": "application/json" },
            payload
          );
          const json = JSON.parse(r.body);
          if (json.error) return sendJSON(res, 502, { ok: false, error: json.error.message || "gemini_error" });
          const text = json.candidates?.[0]?.content?.parts?.[0]?.text || "";
          return sendJSON(res, 200, { ok: true, text });

        } else {
          const openaiKey = OPENAI_API_KEY || String(body.key || "").trim();
          if (!openaiKey) return sendJSON(res, 503, { ok: false, error: "OpenAI API key not set. Please add it in Settings → AI Support." });
          const payload = JSON.stringify({
            model:       "gpt-4o-mini",
            messages:    [{ role: "system", content: systemText }, ...messages],
            max_tokens:  600,
            temperature: 0.7
          });
          const r = await httpsPost(
            "api.openai.com",
            "/v1/chat/completions",
            { "Content-Type": "application/json", "Authorization": `Bearer ${openaiKey}` },
            payload
          );
          const json = JSON.parse(r.body);
          if (json.error) return sendJSON(res, 502, { ok: false, error: json.error.message || "openai_error" });
          const text = json.choices?.[0]?.message?.content || "";
          return sendJSON(res, 200, { ok: true, text });
        }
      } catch (e) {
        return sendJSON(res, 502, { ok: false, error: "ai_proxy_failed", detail: String(e && e.message || e) });
      }
    }

    // § 8  imgbb — proxy ImgBB image upload (API key stays server-side)
    //       Frontend sends base64 image string in JSON body: { image, name }
    if (route === "imgbb") {
      if (!allowed) return sendJSON(res, 403, { ok: false, error: "domain_not_allowed" });
      if (method !== "POST") {
        res.setHeader("Allow", "POST, OPTIONS");
        return sendJSON(res, 405, { ok: false, error: "method_not_allowed" });
      }
      const rlImg = rateLimitHit(`${ip}:imgbb`);
      res.setHeader("X-RateLimit-Limit",     String(RATE_LIMIT_MAX));
      res.setHeader("X-RateLimit-Remaining", String(rlImg.remaining));
      if (!rlImg.ok) {
        res.setHeader("Retry-After", String(Math.ceil(rlImg.resetIn / 1000)));
        return sendJSON(res, 429, { ok: false, error: "rate_limited" });
      }
      try {
        const body    = await parseBody(req);
        const imgbbKey = IMGBB_API_KEY || String(body.key || "").trim();
        if (!imgbbKey) return sendJSON(res, 503, { ok: false, error: "ImgBB API key not set. Please add it in Settings → ImgBB." });
        const image = String(body.image || "").trim();
        if (!image) return sendJSON(res, 400, { ok: false, error: "image_required" });
        const qs       = require("querystring");
        const postBody = qs.stringify({ image, name: String(body.name || "upload") });
        const r = await httpsPost(
          "api.imgbb.com",
          `/1/upload?key=${encodeURIComponent(imgbbKey)}`,
          { "Content-Type": "application/x-www-form-urlencoded" },
          postBody
        );
        const json = JSON.parse(r.body);
        if (!json.success) return sendJSON(res, 502, { ok: false, error: (json.error && json.error.message) || "imgbb_upload_failed" });
        return sendJSON(res, 200, { ok: true, url: json.data.url, deleteUrl: json.data.delete_url });
      } catch (e) {
        return sendJSON(res, 502, { ok: false, error: "imgbb_proxy_failed", detail: String(e && e.message || e) });
      }
    }

    // ── GET/HEAD-only routes below ──────────────────────────────────────────
    if (!["GET", "HEAD"].includes(method)) {
      res.setHeader("Allow", "GET, HEAD, OPTIONS");
      return sendJSON(res, 405, { ok: false, error: "method_not_allowed", method });
    }

    // Rate limit (per ip+route)
    const rl = rateLimitHit(`${ip}:${route || "unknown"}`);
    res.setHeader("X-RateLimit-Limit",     String(RATE_LIMIT_MAX));
    res.setHeader("X-RateLimit-Remaining", String(rl.remaining));
    if (!rl.ok) {
      res.setHeader("Retry-After", String(Math.ceil(rl.resetIn / 1000)));
      return sendJSON(res, 429, { ok: false, error: "rate_limited", retryInMs: rl.resetIn });
    }

    // ── Integrity gate (file presence + domain) ────────────────────────────
    let integrity = null;
    if (!_checkMod) {
      integrity = { ok: false, error: "service_unavailable",
                    _internal: { loadError: _checkLoadError } };
    } else {
      try { integrity = _checkMod.check(req); }
      catch (e) {
        integrity = { ok: false, error: "service_unavailable",
                      _internal: { thrown: String(e && e.message || e) } };
      }
    }

    if (route === "config") {
      if (!integrity.ok) {
        const status = integrity.error === "domain_not_allowed" ? 403 : 503;
        return sendJSON(res, status, { ok: false, error: integrity.error });
      }
      return sendJSON(res, 200, { ok: true, cfg: { ...FIREBASE_CFG, adminEmail: ADMIN_EMAIL } });
    }

    if (route === "watchdog") {
      if (!allowed) return sendJSON(res, 403, { ok: false, error: "domain_not_allowed", host });
      if (!integrity.ok) {
        return sendJSON(res, 503, { ok: false, error: integrity.error, ts: Date.now() });
      }
      return sendJSON(res, 200, { ok: true, ts: Date.now() });
    }

    if (route === "health") {
      return sendJSON(res, 200, {
        ok: true,
        status: integrity.ok ? "healthy" : "degraded",
        ts: Date.now(),
      });
    }

    if (route === "check") {
      const tokenIn  = (req.headers["x-integrity-token"]
        || (req.url || "").match(/[?&]token=([^&]+)/)?.[1] || "");
      const tokenEnv = process.env.INTEGRITY_TOKEN || "";
      const isOwner  = tokenEnv && tokenIn === tokenEnv;
      if (isOwner) {
        let detail = null;
        try { detail = _checkMod ? _checkMod.checkIntegrity() : null; } catch (_) {}
        return sendJSON(res, 200, {
          ok: integrity.ok,
          error: integrity.ok ? null : integrity.error,
          host,
          allowed,
          loadError: _checkLoadError,
          detail,
        });
      }
      return sendJSON(res, integrity.ok ? 200 : 503, {
        ok: integrity.ok,
        status: integrity.ok ? "healthy" : "degraded",
        ts: Date.now(),
      });
    }

    return sendJSON(res, 404, { ok: false, error: "not_found", url: req.url || "" });
  } catch (e) {
    return sendJSON(res, 500, { ok: false, error: "server_error", detail: String(e && e.message || e) });
  }
};
