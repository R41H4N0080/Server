/*
═══════════════════════════════════════════
        PRIVATE VAULT SYSTEM INFO
═══════════════════════════════════════════

Total JS Lines  : 3346
Version         : 5.0.0
Credit          : RAIHAN
Project         : Private Vault – Secure Account Manager

Status          : LIVE
Security        : Enabled (2FA + Vault Protection)
Database        : Firebase Realtime DB

Features:
- Account Vault System
- Bulk Parser Tool
- TXT / JSON Export
- 2FA TOTP Support
- AI Assistant Integration

Note:
This script handles secure account operations.
Do not modify or distribute without permission.

═══════════════════════════════════════════
*/
import { initializeApp, getApps } from "https://www.gstatic.com/firebasejs/11.1.0/firebase-app.js";
import {
  getAuth, signInWithEmailAndPassword, signOut,
  createUserWithEmailAndPassword, onAuthStateChanged,
  updatePassword, EmailAuthProvider, reauthenticateWithCredential
} from "https://www.gstatic.com/firebasejs/11.1.0/firebase-auth.js";
import {
  getDatabase, ref, push, set, update, remove, onValue, get
} from "https://www.gstatic.com/firebasejs/11.1.0/firebase-database.js";

// ══════════════════════════════════════════════════════
// FIREBASE CONFIG  ·  fetched from secure backend (/api/config)
// If backend unreachable OR domain not allowed → website locked.
// ══════════════════════════════════════════════════════
function _vaultLockScreen(title, msg) {
  // Build the lock screen via DOM API (no innerHTML w/ caller strings) so
  // it cannot be turned into an XSS vector if the inputs are ever derived
  // from network data. Also stops every interval/timeout to freeze the page.
  try {
    // Wipe any pending timers so background polling can't keep hammering.
    const hi = setTimeout(()=>{},0);
    for (let i = 1; i <= hi; i++) { try { clearTimeout(i); clearInterval(i); } catch(_){} }
    // Replace document with a sealed DOM tree.
    document.documentElement.replaceChildren();
    const head = document.createElement("head");
    const meta = document.createElement("meta"); meta.setAttribute("charset","UTF-8"); head.appendChild(meta);
    const vp   = document.createElement("meta"); vp.setAttribute("name","viewport"); vp.setAttribute("content","width=device-width, initial-scale=1.0"); head.appendChild(vp);
    const ttl  = document.createElement("title"); ttl.textContent = "Service Unavailable"; head.appendChild(ttl);
    const style = document.createElement("style");
    style.textContent = "body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0a0e1a;color:#e6edf7;padding:24px;text-align:center}.box{max-width:440px}.ic{width:64px;height:64px;margin:0 auto 18px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:rgba(239,68,68,.12);color:#ef4444;font-size:32px;border:1px solid rgba(239,68,68,.3)}h1{font-size:22px;margin:0 0 10px;font-weight:700}p{font-size:14px;line-height:1.55;color:#94a3b8;margin:0 0 6px}.tag{margin-top:18px;font-size:11px;color:#475569;letter-spacing:.08em;text-transform:uppercase}.btn{display:inline-block;margin-top:18px;padding:9px 18px;border-radius:8px;background:#3b82f6;color:#fff;border:none;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none}";
    head.appendChild(style);
    document.documentElement.appendChild(head);
    const body = document.createElement("body");
    const box  = document.createElement("div"); box.className = "box";
    const ic   = document.createElement("div"); ic.className = "ic"; ic.textContent = "⛔"; box.appendChild(ic);
    const h    = document.createElement("h1"); h.textContent = String(title || "Service Unavailable"); box.appendChild(h);
    const p    = document.createElement("p");  p.textContent = String(msg   || "Cannot continue."); box.appendChild(p);
    const btn  = document.createElement("button"); btn.className="btn"; btn.textContent="Reload"; btn.onclick = ()=>location.reload(); box.appendChild(btn);
    const tag  = document.createElement("div"); tag.className = "tag"; tag.textContent = "Private Vault · Secure Mode"; box.appendChild(tag);
    body.appendChild(box);
    document.documentElement.appendChild(body);
  } catch(_) {
    try {
      document.body && (document.body.textContent = String(title) + " — " + String(msg));
    } catch(__){}
  }
  // Mark global state and bail out hard.
  try { window._vaultLocked = true; } catch(_) {}
  throw new Error("vault_locked");
}

let FIREBASE_CFG;
try {
  const _r = await fetch("/api/config", { cache: "no-store", credentials: "same-origin" });
  if (_r.status === 403) {
    _vaultLockScreen("Domain Not Authorized",
      "This website is locked to specific domains. Access from this URL is blocked.");
  }
  if (!_r.ok) throw new Error("config_http_" + _r.status);
  const _j = await _r.json();
  if (!_j.ok || !_j.cfg) throw new Error("config_invalid");
  FIREBASE_CFG = _j.cfg;
  window._vaultRawCfg = _j;
} catch (e) {
  _vaultLockScreen("Backend Unreachable",
    "Cannot reach the secure backend. The website cannot run without it. Please try again later.");
}

const app = getApps().length === 0 ? initializeApp(FIREBASE_CFG) : getApps()[0];

// ─── WATCHDOG: pings backend every 15s. 2 fails → lock UI ───
// Closure-scoped state so console can't reset the fail counter.
// Exposes window.VaultBackend.status = { online, lastOk, lastError, latencyMs, fails }
window.VaultBackend = (function _vaultWatchdog(){
  const state = { online: true, lastOk: Date.now(), lastError: null, latencyMs: 0, fails: 0, locked: false };
  const listeners = new Set();
  function notify(){ for (const fn of listeners) { try { fn(state); } catch(_) {} } }

  async function ping(){
    if (state.locked) return state;
    const t0 = performance.now();
    try {
      const r = await fetch("/api/watchdog", { cache:"no-store", credentials:"same-origin" });
      if (!r.ok) throw new Error("http_" + r.status);
      const j = await r.json();
      if (!j || !j.ok) throw new Error("invalid_payload");
      state.fails = 0;
      state.online = true;
      state.lastOk = Date.now();
      state.lastError = null;
      state.latencyMs = Math.round(performance.now() - t0);
    } catch(e) {
      state.fails++;
      state.online = false;
      state.lastError = e && e.message || String(e);
      state.latencyMs = Math.round(performance.now() - t0);
      if (state.fails >= 2) {
        state.locked = true;
        notify();
        _vaultLockScreen("Backend Disconnected",
          "Lost connection to the secure backend. Reload the page once your connection is restored.");
        return state;
      }
    }
    notify();
    // Reflect status in sidebar dot if present.
    try {
      document.querySelectorAll(".sys-health-dot").forEach(el => {
        el.classList.toggle("ok",   state.online);
        el.classList.toggle("warn", !state.online && state.fails === 1);
        el.classList.toggle("bad",  !state.online && state.fails >= 2);
        el.title = state.online
          ? `Backend OK · ${state.latencyMs}ms`
          : `Backend issue (${state.fails}× fail) · ${state.lastError || ""}`;
      });
    } catch(_) {}
    return state;
  }
  setInterval(ping, 15000);
  // Run a fast follow-up if the tab regains focus or comes back online.
  window.addEventListener("focus",  () => ping());
  window.addEventListener("online", () => ping());
  window.addEventListener("offline", () => {
    state.online = false;
    state.lastError = "Browser is offline";
    state.fails = Math.max(state.fails, 1);
    notify();
  });

  return {
    get status(){ return Object.assign({}, state); },
    ping,
    onChange(fn){ listeners.add(fn); return () => listeners.delete(fn); },
    require(){
      // Hard gate for sensitive actions: throws if backend is offline.
      if (state.locked || !state.online) {
        throw new Error("Backend offline — action blocked for security.");
      }
      return true;
    }
  };
})();
const auth = getAuth(app);
const db = getDatabase(app);

let ADMIN_EMAIL = (window._vaultRawCfg && window._vaultRawCfg.cfg && window._vaultRawCfg.cfg.adminEmail) || "admin@vaultadmin.local";
const ADMIN_COLLECTION = "accounts";
const ADMIN_CFG_COLLECTION = "admin_config";
const ADMIN_SETTINGS_PATH = "admin_settings";
const LOG_COLLECTION = "vault_logs";

// ══════════════════════════════════════════════════════
// VAULT DEBUG SYSTEM
// ══════════════════════════════════════════════════════
const VaultDebug = (() => {
  let _errorCount = 0;
  let _warnCount = 0;
  const _isDebug = new URLSearchParams(location.search).has("debug");
  const _errorLog = [];

  function _badge() {
    let el = document.getElementById("vault-debug-badge");
    if (!el) {
      el = document.createElement("div");
      el.id = "vault-debug-badge";
      el.className = "vault-debug-badge";
      el.onclick = () => toggleDebugPanel();
      document.body.appendChild(el);
    }
    el.textContent = `⚠ ${_errorCount} E · ${_warnCount} W`;
    el.style.display = "none";
  }

  function _append(level, args) {
    if (!_isDebug) return;
    const panel = document.getElementById("vault-debug-log");
    if (!panel) return;
    const line = document.createElement("div");
    line.className = `vdbg-line vdbg-${level}`;
    line.textContent = `[${new Date().toLocaleTimeString()}] [${level.toUpperCase()}] ${args.join(" ")}`;
    panel.appendChild(line);
    panel.scrollTop = panel.scrollHeight;
  }

  const _record = (level, args) => {
    const msg = args.map(a => (typeof a === "object" ? JSON.stringify(a) : String(a))).join(" ");
    _errorLog.push({ level, msg, time: new Date().toLocaleTimeString() });
    if (_errorLog.length > 100) _errorLog.shift();
  };
  return {
    log: (...a)   => { if (_isDebug) console.log("[Vault]", ...a); _append("log", a); },
    warn: (...a)  => { _warnCount++; console.warn("[Vault]", ...a); _append("warn", a); _badge(); _record("warn", a); },
    error: (...a) => { _errorCount++; console.error("[Vault]", ...a); _append("error", a); _badge(); _record("error", a); },
    alert: (msg, type = "error") => { showToast(msg, type); },
    reset: () => { _errorCount = 0; _warnCount = 0; _badge(); },
    _getErrors: () => _errorLog.filter(e => e.level === "error" || e.level === "warn"),
    isDebug: _isDebug
  };
})();

function _createDebugPanel() {
  let panel = document.getElementById("vault-debug-panel");
  if (panel) return panel;
  panel = document.createElement("div");
  panel.id = "vault-debug-panel";
  panel.className = "vault-debug-panel";
  panel.innerHTML = `<div class="vdbg-header"><span>&#x1F527; Vault Debug Console</span><button onclick="document.getElementById('vault-debug-log').innerHTML='';VaultDebug.reset();">Clear</button><button onclick="this.closest('.vault-debug-panel').remove();">&#x2715;</button></div><div class="vault-debug-log" id="vault-debug-log"></div>`;
  document.body.appendChild(panel);
  return panel;
}

window.toggleDebugPanel = function() {
  const panel = document.getElementById("vault-debug-panel");
  if (panel) { panel.remove(); return; }
  _createDebugPanel();
};

if (VaultDebug.isDebug) {
  document.addEventListener("DOMContentLoaded", _createDebugPanel);
}

// ══════════════════════════════════════════════════════
// GLOBAL ERROR CAPTURE — catches ALL uncaught JS errors
// ══════════════════════════════════════════════════════
window.onerror = function(message, source, lineno, colno, error) {
  const loc = source ? `${source.split("/").pop()}:${lineno}:${colno}` : "unknown";
  VaultDebug.error(`[JS] ${message} @ ${loc}`);
  return false;
};
window.onunhandledrejection = function(event) {
  const reason = event.reason
    ? (event.reason.message || String(event.reason))
    : "Unhandled Promise rejection";
  VaultDebug.error(`[Promise] ${reason}`);
};

// ══════════════════════════════════════════════════════
// STATE
// ══════════════════════════════════════════════════════
let allAccounts = [];
let otpIntervals = {};
let deleteTargetId = null;
let unsubscribeAccounts = null;
window._settings = {};
let _weakAlertShown = false;
let _isFirstRender = true;
let _pinnedIds = new Set(JSON.parse(localStorage.getItem("pinned_accounts") || "[]"));

// ── Cached DOM elements ──
const _dom = {
  get grid()      { return document.getElementById("accounts-grid"); },
  get statsBar()  { return document.getElementById("stats-bar"); },
  get emptyState(){ return document.getElementById("empty-state"); },
  get countLabel(){ return document.getElementById("account-count-label"); },
  get searchInput(){ return document.getElementById("search-input"); },
  get filterPlatform(){ return document.getElementById("filter-platform"); },
  get filterStatus(){ return document.getElementById("filter-status"); },
};
// Will be overwritten from Firebase after login

// ══════════════════════════════════════════════════════
// VAULT ACTIVITY LOG SYSTEM  ·  Credit: RAIHAN
// ══════════════════════════════════════════════════════
const LOG_ICONS = {
  added:          "🟢",
  edited:         "✏️",
  deleted:        "🗑️",
  status_live:    "✅",
  status_dead:    "💀",
  recheck:        "🔄",
  bulk_added:     "📦",
  bulk_deleted:   "🗑️",
};

const LOG_LABELS = {
  added:          "Account Added",
  edited:         "Account Edited",
  deleted:        "Account Deleted",
  status_live:    "Marked Live",
  status_dead:    "Marked Dead",
  recheck:        "Recheck Scan",
  bulk_added:     "Bulk Added",
  bulk_deleted:   "Bulk Deleted",
};

async function addVaultLog(type, accountName, platform, detail = "") {
  try {
    const entry = {
      type,
      accountName: accountName || "Unknown",
      platform: platform || "other",
      detail,
      timestamp: Date.now()
    };
    // Mirror the latest events into a small in-memory ring so the AI
    // assistant can show "recent activity" instantly without re-querying.
    if (!window._recentVaultLogs) window._recentVaultLogs = [];
    window._recentVaultLogs.push({
      action: type, target: accountName || "", platform,
      message: detail || `${type} · ${accountName || ""}`,
      ts: entry.timestamp,
    });
    if (window._recentVaultLogs.length > 50) window._recentVaultLogs.shift();
    await push(ref(db, LOG_COLLECTION), entry);
    // If log panel is open, refresh it automatically
    const panel = document.getElementById("activity-log-overlay");
    if (panel) {
      window._alReloadLogs && window._alReloadLogs();
    }
  } catch (err) {
    console.error("addVaultLog failed:", err);
    if (typeof showToast === "function") {
      showToast("Log save failed: " + (err.message || err), "error");
    }
  }
}

function _getPlatformShort(p) {
  const m = { facebook:"FB", instagram:"IG", gmail:"Gmail", twitter:"Twitter", tiktok:"TikTok", snapchat:"Snap", youtube:"YouTube", discord:"Discord", telegram:"Telegram", github:"GitHub" };
  return m[p] || (p ? p.charAt(0).toUpperCase() + p.slice(1) : "");
}

function _formatLogTime(ts) {
  const d = new Date(ts);
  const now = new Date();
  const diffMs = now - d;
  const diffMin = Math.floor(diffMs / 60000);
  const diffH = Math.floor(diffMs / 3600000);
  const diffD = Math.floor(diffMs / 86400000);
  if (diffMin < 1) return "Just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffH < 24) return `${diffH}h ago`;
  if (diffD < 7) return `${diffD}d ago`;
  return d.toLocaleDateString("en-GB", { day:"2-digit", month:"short", year:"numeric" });
}

function _formatLogFull(ts) {
  return new Date(ts).toLocaleString("en-GB", {
    day:"2-digit", month:"short", year:"numeric",
    hour:"2-digit", minute:"2-digit", second:"2-digit"
  });
}

window.openActivityLog = async function() {
  if (typeof closeSidebar === "function") closeSidebar();
  const existing = document.getElementById("activity-log-overlay");
  if (existing) { existing.remove(); return; }

  const overlay = document.createElement("div");
  overlay.id = "activity-log-overlay";
  overlay.style.cssText = `position:fixed;inset:0;z-index:9999;display:flex;align-items:flex-start;justify-content:flex-end;padding:16px;background:rgba(0,0,0,0.55);backdrop-filter:blur(4px);`;
  overlay.innerHTML = `
    <div id="activity-log-panel" style="width:min(480px,100%);max-height:calc(100vh - 32px);display:flex;flex-direction:column;background:var(--bg2,#0f1320);border:1px solid var(--border,rgba(255,255,255,0.08));border-radius:14px;box-shadow:0 8px 48px rgba(0,0,0,0.6);overflow:hidden;">
      <div style="display:flex;align-items:center;justify-content:space-between;padding:16px 18px;border-bottom:1px solid var(--border,rgba(255,255,255,0.08));flex-shrink:0;">
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-size:18px;">📋</span>
          <div>
            <div style="font-weight:700;font-size:15px;color:var(--text1,#f1f5f9);">Activity Log</div>
            <div style="font-size:11px;color:var(--text3,#64748b);margin-top:2px;">All account changes tracked in real-time</div>
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:8px;">
          <button id="al-filter-btn" onclick="window._alToggleFilter()" style="background:rgba(255,255,255,0.05);border:1px solid var(--border,rgba(255,255,255,0.08));color:var(--text2,#94a3b8);padding:5px 10px;border-radius:7px;cursor:pointer;font-size:12px;">Filter</button>
          <button id="al-refresh-btn" onclick="window._alReloadLogs && window._alReloadLogs()" title="Refresh Logs" style="background:rgba(255,255,255,0.05);border:1px solid var(--border,rgba(255,255,255,0.08));color:var(--text2,#94a3b8);width:30px;height:30px;border-radius:7px;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center;">🔄</button>
          <button onclick="document.getElementById('activity-log-overlay').remove();" style="background:rgba(255,255,255,0.05);border:1px solid var(--border,rgba(255,255,255,0.08));color:var(--text2,#94a3b8);width:30px;height:30px;border-radius:7px;cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;">✕</button>
        </div>
      </div>
      <div id="al-filter-row" style="display:none;padding:10px 18px;border-bottom:1px solid var(--border,rgba(255,255,255,0.08));flex-shrink:0;gap:6px;flex-wrap:wrap;display:none;">
        <button class="al-fbtn al-factive" data-f="all" onclick="window._alFilter('all')">All</button>
        <button class="al-fbtn" data-f="added" onclick="window._alFilter('added')">Added</button>
        <button class="al-fbtn" data-f="edited" onclick="window._alFilter('edited')">Edited</button>
        <button class="al-fbtn" data-f="deleted" onclick="window._alFilter('deleted')">Deleted</button>
        <button class="al-fbtn" data-f="status_dead" onclick="window._alFilter('status_dead')">Dead</button>
        <button class="al-fbtn" data-f="status_live" onclick="window._alFilter('status_live')">Live</button>
        <button class="al-fbtn" data-f="recheck" onclick="window._alFilter('recheck')">Recheck</button>
      </div>
      <div id="al-stats" style="display:flex;gap:0;border-bottom:1px solid var(--border,rgba(255,255,255,0.08));flex-shrink:0;"></div>
      <div id="al-body" style="overflow-y:auto;flex:1;padding:8px 0;">
        <div style="display:flex;align-items:center;justify-content:center;padding:48px;color:var(--text3,#64748b);">
          <span style="font-size:13px;">Loading logs...</span>
        </div>
      </div>
      <div style="padding:10px 18px;border-top:1px solid var(--border,rgba(255,255,255,0.08));display:flex;align-items:center;justify-content:space-between;flex-shrink:0;">
        <span id="al-count" style="font-size:11px;color:var(--text3,#64748b);">—</span>
        <button onclick="window._alClearLogs()" style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);color:#ef4444;padding:5px 12px;border-radius:7px;cursor:pointer;font-size:11px;">Clear All Logs</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener("click", e => { if (e.target === overlay) overlay.remove(); });

  // Inject filter button styles
  if (!document.getElementById("al-style")) {
    const s = document.createElement("style");
    s.id = "al-style";
    s.textContent = `.al-fbtn{background:rgba(255,255,255,0.04);border:1px solid var(--border,rgba(255,255,255,0.08));color:var(--text3,#64748b);padding:4px 10px;border-radius:20px;cursor:pointer;font-size:11px;transition:all .15s}.al-fbtn.al-factive{background:rgba(59,130,246,0.15);border-color:rgba(59,130,246,0.4);color:#60a5fa}.al-log-item{display:flex;align-items:flex-start;gap:12px;padding:11px 18px;border-bottom:1px solid rgba(255,255,255,0.04);transition:background .15s}.al-log-item:hover{background:rgba(255,255,255,0.03)}.al-log-item:last-child{border-bottom:none}`;
    document.head.appendChild(s);
  }

  window._alCurrentFilter = "all";
  window._allLogsData = [];
  window._alFilterShown = false;

  window._alToggleFilter = function() {
    window._alFilterShown = !window._alFilterShown;
    const row = document.getElementById("al-filter-row");
    if (row) row.style.display = window._alFilterShown ? "flex" : "none";
  };

  window._alFilter = function(f) {
    window._alCurrentFilter = f;
    document.querySelectorAll(".al-fbtn").forEach(b => b.classList.toggle("al-factive", b.dataset.f === f));
    window._alRenderLogs(window._allLogsData);
  };

  window._alRenderLogs = function(logs) {
    const body = document.getElementById("al-body");
    const countEl = document.getElementById("al-count");
    if (!body) return;
    const f = window._alCurrentFilter;
    const filtered = f === "all" ? logs : logs.filter(l => l.type === f);
    if (filtered.length === 0) {
      body.innerHTML = `<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:48px;gap:10px;color:var(--text3,#64748b);"><span style="font-size:32px;">📭</span><span style="font-size:13px;">No logs found</span></div>`;
      if (countEl) countEl.textContent = "0 events";
      return;
    }
    if (countEl) countEl.textContent = `${filtered.length} event${filtered.length !== 1 ? "s" : ""}`;
    body.innerHTML = filtered.map(log => {
      const icon = LOG_ICONS[log.type] || "📝";
      const label = LOG_LABELS[log.type] || log.type;
      const plat = _getPlatformShort(log.platform);
      const timeAgo = _formatLogTime(log.timestamp);
      const timeFull = _formatLogFull(log.timestamp);
      const colorMap = {
        added:"rgba(34,197,94,0.12)", edited:"rgba(59,130,246,0.10)", deleted:"rgba(239,68,68,0.10)",
        status_dead:"rgba(239,68,68,0.10)", status_live:"rgba(34,197,94,0.12)", recheck:"rgba(245,158,11,0.10)",
        bulk_added:"rgba(139,92,246,0.10)", bulk_deleted:"rgba(239,68,68,0.10)"
      };
      const dotColor = {
        added:"#22c55e", edited:"#3b82f6", deleted:"#ef4444",
        status_dead:"#ef4444", status_live:"#22c55e", recheck:"#f59e0b",
        bulk_added:"#8b5cf6", bulk_deleted:"#ef4444"
      };
      return `<div class="al-log-item">
        <div style="width:34px;height:34px;border-radius:9px;background:${colorMap[log.type]||"rgba(255,255,255,0.05)"};display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0;">${icon}</div>
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
            <div style="font-size:13px;font-weight:600;color:var(--text1,#f1f5f9);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escHtml(log.accountName)}</div>
            <div style="font-size:10px;color:var(--text3,#64748b);flex-shrink:0;" title="${timeFull}">${timeAgo}</div>
          </div>
          <div style="display:flex;align-items:center;gap:6px;margin-top:3px;">
            <span style="font-size:10px;padding:1px 6px;border-radius:10px;background:${colorMap[log.type]||"rgba(255,255,255,0.05)"};color:${dotColor[log.type]||"var(--text3)"};font-weight:600;">${label}</span>
            ${plat ? `<span style="font-size:10px;color:var(--text3,#64748b);">${escHtml(plat)}</span>` : ""}
          </div>
          ${log.detail ? `<div style="font-size:11px;color:var(--text3,#64748b);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${escHtml(log.detail)}">${escHtml(log.detail)}</div>` : ""}
        </div>
      </div>`;
    }).join("");
  };

  window._alRenderStats = function(logs) {
    const statsEl = document.getElementById("al-stats");
    if (!statsEl) return;
    const counts = {};
    logs.forEach(l => { counts[l.type] = (counts[l.type] || 0) + 1; });
    const total = logs.length;
    const added = (counts.added || 0) + (counts.bulk_added || 0);
    const edited = counts.edited || 0;
    const deleted = (counts.deleted || 0) + (counts.bulk_deleted || 0);
    const dead = counts.status_dead || 0;
    statsEl.innerHTML = [
      ["Total", total, "#60a5fa"],
      ["Added", added, "#22c55e"],
      ["Edited", edited, "#3b82f6"],
      ["Deleted", deleted, "#ef4444"],
      ["Dead", dead, "#f87171"],
    ].map(([l, v, c]) => `<div style="flex:1;padding:10px 8px;text-align:center;border-right:1px solid var(--border,rgba(255,255,255,0.08));"><div style="font-size:17px;font-weight:700;color:${c};">${v}</div><div style="font-size:10px;color:var(--text3,#64748b);margin-top:2px;">${l}</div></div>`).join("") + "</div>";
    statsEl.lastElementChild && statsEl.lastElementChild.style.setProperty("border-right", "none");
    statsEl.querySelectorAll("div[style*='border-right']").forEach((el, i, arr) => {
      if (i === arr.length - 1) el.style.borderRight = "none";
    });
  };

  window._alClearLogs = async function() {
    if (!confirm("All activity logs will be permanently deleted. Continue?")) return;
    try {
      await remove(ref(db, LOG_COLLECTION));
      window._allLogsData = [];
      window._alRenderLogs([]);
      window._alRenderStats([]);
      showToast("Activity logs cleared.", "info");
    } catch (err) {
      showToast("Failed to clear logs: " + err.message, "error");
    }
  };

  // Load logs from Firebase — reusable reload function
  window._alReloadLogs = async function() {
    const body = document.getElementById("al-body");
    if (body) body.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;padding:48px;color:var(--text3,#64748b);"><span style="font-size:13px;">Loading logs...</span></div>`;
    try {
      const snap = await new Promise((res, rej) =>
        onValue(ref(db, LOG_COLLECTION), res, rej, { onlyOnce: true })
      );
      const raw = snap.val() || {};
      const logs = Object.entries(raw)
        .map(([id, v]) => ({ id, ...v }))
        .sort((a, b) => b.timestamp - a.timestamp);
      window._allLogsData = logs;
      window._alRenderStats(logs);
      window._alRenderLogs(logs);
    } catch (err) {
      const body = document.getElementById("al-body");
      if (body) {
        body.replaceChildren();
        const e = document.createElement("div");
        e.style.cssText = "padding:32px;text-align:center;color:#ef4444;font-size:13px;";
        e.textContent = "Failed to load logs: " + (err && err.message || String(err));
        body.appendChild(e);
      }
    }
  };

  await window._alReloadLogs();
};

// ══════════════════════════════════════════════════════
// FIREBASE-BACKED SETTINGS  ·  Credit: RAIHAN
// ══════════════════════════════════════════════════════
const LS_KEYS = {
  imgbb_key:   "imgbb_api_key",
  openai_key:  "openai_api_key",
  gemini_key:  "gemini_api_key",
  ai_provider: "ai_provider",
  ai_enabled:  "ai_enabled",
};

function _applyLocalStorageFallback() {
  // Read from localStorage into _settings for any missing key
  Object.entries(LS_KEYS).forEach(([fbKey, lsKey]) => {
    if (!window._settings[fbKey]) {
      const v = localStorage.getItem(lsKey);
      if (v) window._settings[fbKey] = v;
    }
  });
}

async function loadAdminSettings() {
  return new Promise((resolve) => {
    // 5-second safety timeout — never block login
    const timer = setTimeout(() => {
      console.warn("admin_settings load timed-out — using localStorage fallback");
      _applyLocalStorageFallback();
      resolve(window._settings);
    }, 5000);

    const settingsRef = ref(db, ADMIN_SETTINGS_PATH);
    onValue(settingsRef, (snap) => {
      clearTimeout(timer);
      const val = snap.val() || {};
      window._settings = val;

      // Load pinned accounts from Firebase
      if (val.pinned_ids) {
        try { _pinnedIds = new Set(JSON.parse(val.pinned_ids)); } catch {}
      }

      // Migrate localStorage → Firebase for any key not yet in Firebase
      const updates = {};
      Object.entries(LS_KEYS).forEach(([fbKey, lsKey]) => {
        if (!val[fbKey]) {
          const lsVal = localStorage.getItem(lsKey);
          if (lsVal) { updates[fbKey] = lsVal; window._settings[fbKey] = lsVal; }
        }
      });
      // Migrate pinned_ids from localStorage if not in Firebase
      if (!val.pinned_ids) {
        const lsPinned = localStorage.getItem("pinned_accounts");
        if (lsPinned && lsPinned !== "[]") {
          updates.pinned_ids = lsPinned;
          try { _pinnedIds = new Set(JSON.parse(lsPinned)); } catch {}
        }
      }
      if (Object.keys(updates).length) {
        update(ref(db, ADMIN_SETTINGS_PATH), updates).catch(() => {});
      }
      resolve(window._settings);
    }, (err) => {
      // Firebase RTDB rules denied access — fall back silently
      clearTimeout(timer);
      console.warn("admin_settings read denied:", err.message, "— check Firebase RTDB rules");
      _applyLocalStorageFallback();
      resolve(window._settings);
    }, { onlyOnce: true });
  });
}

async function saveSetting(key, value) {
  window._settings[key] = value;
  // Mirror to localStorage so fallback always works
  const lsKey = LS_KEYS[key];
  if (lsKey) localStorage.setItem(lsKey, value);
  try {
    await update(ref(db, ADMIN_SETTINGS_PATH), { [key]: value });
  } catch (e) {
    console.warn("saveSetting Firebase write failed:", e.message);
    // Already saved to localStorage above, so no data loss
  }
}

// ══════════════════════════════════════════════════════
// PRE-LOADER ENGINE  ·  Credit: RAIHAN
// ══════════════════════════════════════════════════════
const _plEl    = document.getElementById("preloader");
const _plBar   = document.getElementById("preloader-bar-fill");
const _plStat  = document.getElementById("preloader-status");
const _plPct   = document.getElementById("preloader-pct");
let   _plDone  = false;

function _setProgress(pct, status) {
  if (_plBar)  _plBar.style.width  = Math.min(pct, 100) + "%";
  if (_plPct)  _plPct.textContent  = Math.min(Math.round(pct), 100) + "%";
  if (status && _plStat) _plStat.textContent = status;
}

function hidePreloader() {
  if (_plDone) return;
  _plDone = true;
  clearInterval(_plProgressInterval);
  _setProgress(100, "Ready");
  setTimeout(() => {
    if (_plEl) {
      _plEl.classList.add("hide");
      setTimeout(() => { if (_plEl) _plEl.style.display = "none"; }, 500);
    }
  }, 280);
}

let _plPct2 = 0;
const _plProgressInterval = setInterval(() => {
  if (_plDone) return;
  if (_plPct2 < 40) {
    _plPct2 += Math.random() * 18 + 4;
    _setProgress(_plPct2, "Initializing...");
  } else if (_plPct2 < 70) {
    _plPct2 += Math.random() * 8 + 2;
    _setProgress(_plPct2, "Connecting to Firebase...");
  } else if (_plPct2 < 88) {
    _plPct2 += Math.random() * 3 + 0.5;
    _setProgress(_plPct2, "Checking session...");
  }
}, 220);

// ══════════════════════════════════════════════════════
// TOTP ENGINE (RFC 6238) — pure WebCrypto
// ══════════════════════════════════════════════════════
const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(str) {
  const s = str.toUpperCase().replace(/=+$/, "").replace(/\s/g, "");
  let bits = 0, value = 0;
  const output = [];
  for (let i = 0; i < s.length; i++) {
    const idx = BASE32_CHARS.indexOf(s[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

async function generateTOTP(secret) {
  try {
    const keyBytes = base32Decode(secret);
    const counter = Math.floor(Date.now() / 1000 / 30);
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    const high = Math.floor(counter / 0x100000000);
    const low = counter >>> 0;
    view.setUint32(0, high, false);
    view.setUint32(4, low, false);

    const key = await crypto.subtle.importKey(
      "raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, buf);
    const hash = new Uint8Array(sig);
    const offset = hash[hash.length - 1] & 0x0f;
    const code = ((hash[offset] & 0x7f) << 24)
      | ((hash[offset + 1] & 0xff) << 16)
      | ((hash[offset + 2] & 0xff) << 8)
      | (hash[offset + 3] & 0xff);
    return String(code % 1000000).padStart(6, "0");
  } catch {
    return "------";
  }
}

function getTOTPRemaining() {
  return 30 - (Math.floor(Date.now() / 1000) % 30);
}

function getTOTPProgress() {
  return (getTOTPRemaining() / 30) * 100;
}

// ══════════════════════════════════════════════════════
// PAGE NAVIGATION
// ══════════════════════════════════════════════════════
window.showPage = function(page) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.getElementById("page-" + page).classList.add("active");
  if (page === "login" && typeof _generateCaptcha === "function") {
    setTimeout(_generateCaptcha, 50);
  }
  if (page === "dashboard") setupAccountsListener();
  if (page === "settings") {
    updateSettingsCount();
    // Restore AI & API key fields from Firebase cache
    const enabled = window._settings.ai_enabled === "1";
    const toggle = document.getElementById("ai-toggle");
    if (toggle) toggle.checked = enabled;
    const panel = document.getElementById("ai-settings-panel");
    if (panel) panel.style.display = enabled ? "block" : "none";
    showApiKeyState("openai", window._settings.openai_key || "");
    showApiKeyState("gemini", window._settings.gemini_key || "");
    showApiKeyState("imgbb", window._settings.imgbb_key || "");
    switchAIProvider(window._settings.ai_provider || "openai");
    updateFirebaseConnPill();
    // Login security panels
    if (typeof renderLogin2FAPanel === "function") renderLogin2FAPanel();
    if (typeof renderBlockedIPsList === "function") renderBlockedIPsList();
    // Real-time login log listener — shows ALL devices' logs automatically
    _setupLoginLogsListener();
  } else {
    // Tear down the real-time listener when leaving settings
    _teardownLoginLogsListener();
  }
  if (isMobile()) closeSidebar();
  return false;
};

// ── Firebase connection pill updater (Settings page) ──
function updateFirebaseConnPill() {
  const pill = document.getElementById("fb-conn-pill");
  if (!pill) return;
  pill.className = "fb-conn-pill";
  pill.innerHTML = `<span class="fb-conn-dot"></span> Checking…`;
  try {
    const connRef = ref(db, ".info/connected");
    onValue(connRef, (snap) => {
      const ok = snap.val() === true;
      if (pill) {
        pill.className = "fb-conn-pill " + (ok ? "connected" : "offline");
        pill.innerHTML = `<span class="fb-conn-dot"></span> ${ok ? "Connected" : "Offline"}`;
      }
    }, { onlyOnce: true });
  } catch(e) {
    if (pill) {
      pill.className = "fb-conn-pill offline";
      pill.innerHTML = `<span class="fb-conn-dot"></span> Error`;
    }
  }
}

// ══════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════
function showLoginForm(errMsg) {
  hidePreloader();
  document.getElementById("login-loading").classList.add("hidden");
  document.getElementById("login-form").classList.remove("hidden");
  if (errMsg) {
    showLoginError(errMsg);
  }
}

async function initAdmin() {
  // Only use Firebase Auth — no Firestore dependency here.
  // This ensures admin account creation works even if Firestore isn't set up yet.
  try {
    await createUserWithEmailAndPassword(auth, ADMIN_EMAIL, "Admin@1234");
    // New admin created — sign them out so they use the login form
    await signOut(auth);
    showLoginForm();
  } catch (err) {
    if (err.code === "auth/email-already-in-use") {
      // Admin already exists — normal situation after first run
      showLoginForm();
    } else if (err.code === "auth/configuration-not-found" ||
               err.code === "auth/operation-not-allowed") {
      showLoginForm(
        "Firebase Auth not enabled. Please enable Email/Password sign-in in your Firebase Console → Authentication → Sign-in method."
      );
    } else if (err.code === "auth/network-request-failed") {
      showLoginForm("Network error. Check your internet connection.");
    } else if (!FIREBASE_CFG.apiKey || FIREBASE_CFG.apiKey === "__FB_API_KEY__") {
      showLoginForm("Firebase config missing. Check your environment secrets (VITE_FIREBASE_API_KEY etc.).");
    } else {
      console.error("Init error:", err.code, err.message);
      showLoginForm();
    }
  }
}

// ── LOGIN MATH-CAPTCHA (anti-bot) ─────────────────────
// Generates a fresh `?+?=?` puzzle each render. Numbers are
// 1-digit and the result is ≤ 9 (operator is + or − with a
// guaranteed positive 1-digit answer) so users can solve it
// instantly while bots that just submit forms cannot.
window._captcha = { answer: 0, attempts: 0, generatedAt: 0 };

function _generateCaptcha() {
  const ops = ["+", "−"];
  const op = ops[Math.floor(Math.random() * ops.length)];
  let a, b, ans;
  if (op === "+") {
    a = 1 + Math.floor(Math.random() * 7);   // 1-7
    b = 1 + Math.floor(Math.random() * (8 - a)); // ensure a+b ≤ 8
    ans = a + b;
  } else {
    a = 3 + Math.floor(Math.random() * 7);   // 3-9
    b = 1 + Math.floor(Math.random() * (a - 1)); // ensure a-b ≥ 1
    ans = a - b;
  }
  window._captcha = { answer: ans, attempts: 0, generatedAt: Date.now() };
  const aEl = document.getElementById("cq-a");
  const bEl = document.getElementById("cq-b");
  const opEl= document.getElementById("cq-op");
  const inp = document.getElementById("login-captcha");
  const errEl = document.getElementById("captcha-error");
  if (aEl) aEl.textContent = String(a);
  if (bEl) bEl.textContent = String(b);
  if (opEl) opEl.textContent = op;
  if (inp) { inp.value = ""; inp.classList.remove("captcha-ok","captcha-bad"); }
  if (errEl) errEl.classList.add("hidden");
  // Subtle re-roll animation
  const q = document.getElementById("captcha-question");
  if (q) { q.classList.remove("captcha-roll"); void q.offsetWidth; q.classList.add("captcha-roll"); }
}
window._generateCaptcha = _generateCaptcha;

// Auto-init when login page is in DOM (handles both pre- and
// post-DOMContentLoaded loads since this script is large and
// may parse after the event fires).
function _initCaptchaUI() {
  const refresh = document.getElementById("captcha-refresh");
  if (refresh && !refresh._wired) {
    refresh._wired = true;
    refresh.addEventListener("click", _generateCaptcha);
  }
  const inp = document.getElementById("login-captcha");
  if (inp && !inp._wired) {
    inp._wired = true;
    inp.addEventListener("input", () => {
      inp.value = inp.value.replace(/[^0-9]/g, "").slice(0, 2);
      const errEl = document.getElementById("captcha-error");
      if (errEl) errEl.classList.add("hidden");
      inp.classList.remove("captcha-bad");
      if (parseInt(inp.value, 10) === window._captcha.answer) {
        inp.classList.add("captcha-ok");
      } else {
        inp.classList.remove("captcha-ok");
      }
    });
  }
  if (document.getElementById("captcha-question")) _generateCaptcha();
}
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", _initCaptchaUI);
} else {
  _initCaptchaUI();
}

// ══════════════════════════════════════════════════════
// LOGIN SECURITY MODULE — IP detection, rate limiter,
// login history, blocked-IP manager, login-2FA store
// ══════════════════════════════════════════════════════
window.LoginSecurity = (function() {
  // ─── tunables ─────────────────────────────────────
  const MAX_FAILS         = 5;        // wrong attempts before lockout
  const LOCKOUT_MS        = 15 * 60 * 1000;  // 15-minute temporary block
  const FAIL_WINDOW_MS    = 30 * 60 * 1000;  // counter resets after 30 min
  const LOG_KEEP          = 50;       // keep last 50 in RTDB, show last 10
  const LS_FAILS          = "pv_login_fails";
  const LS_BLOCKED_UNTIL  = "pv_blocked_until";
  const LS_BLOCKED_IPS    = "pv_blocked_ips_cache";
  const LS_LOGS_LOCAL     = "pv_login_logs_local";
  const RTDB_LOGS         = "loginLogs";
  const RTDB_BLOCKED      = "blockedIPs";

  let _ipCache = null;        // {ip, country, city, region, isp}
  let _ipFetched = false;

  // ─── Per-browser device identity (persistent UUID) ───
  function getDeviceId() {
    let id = localStorage.getItem("pv_device_id");
    if (!id) {
      id = "dv_" + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
      localStorage.setItem("pv_device_id", id);
    }
    return id;
  }

  // ─── IP / GEO detection ──────────────────────────
  async function getClientIP() {
    if (_ipCache && _ipFetched) return _ipCache;
    const out = { ip: "unknown", country: "?", city: "?", region: "", isp: "" };
    try {
      // Primary: ipify (fast, free, no auth)
      const r = await fetch("https://api.ipify.org?format=json", { cache: "no-store" });
      if (r.ok) {
        const j = await r.json();
        out.ip = j.ip || "unknown";
      }
    } catch (_) { /* offline / blocked */ }
    if (out.ip !== "unknown") {
      try {
        // Geo: ipapi.co (free, ~1k/day, no key needed)
        const g = await fetch(`https://ipapi.co/${encodeURIComponent(out.ip)}/json/`, { cache: "no-store" });
        if (g.ok) {
          const j = await g.json();
          out.country = j.country_name || j.country || "?";
          out.city    = j.city || "?";
          out.region  = j.region || "";
          out.isp     = j.org || j.asn || "";
        }
      } catch (_) {}
    }
    _ipCache = out;
    _ipFetched = true;
    return out;
  }

  function getBrowserInfo() {
    const ua = navigator.userAgent || "";
    let browser = "Unknown", browserVersion = "", os = "Unknown", osVersion = "";

    // Browser + version
    if (/Edg\/(\d+)/.test(ua))                          { browser = "Edge";    browserVersion = RegExp.$1; }
    else if (/OPR\/(\d+)/.test(ua))                     { browser = "Opera";   browserVersion = RegExp.$1; }
    else if (/Chrome\/(\d+)/.test(ua))                  { browser = "Chrome";  browserVersion = RegExp.$1; }
    else if (/Firefox\/(\d+)/.test(ua))                  { browser = "Firefox"; browserVersion = RegExp.$1; }
    else if (/Version\/(\d+).*Safari/.test(ua))          { browser = "Safari";  browserVersion = RegExp.$1; }
    else if (/MSIE (\d+)|Trident\/.*rv:(\d+)/.test(ua)) { browser = "IE";      browserVersion = RegExp.$1 || RegExp.$2; }
    else if (/SamsungBrowser\/(\d+)/.test(ua))           { browser = "Samsung"; browserVersion = RegExp.$1; }
    else if (/UCBrowser\/(\d+)/.test(ua))                { browser = "UC";      browserVersion = RegExp.$1; }

    // OS + version
    if      (/Windows NT 10/.test(ua))         { os = "Windows"; osVersion = "10/11"; }
    else if (/Windows NT 6\.3/.test(ua))        { os = "Windows"; osVersion = "8.1"; }
    else if (/Windows NT 6\.1/.test(ua))        { os = "Windows"; osVersion = "7"; }
    else if (/Windows NT/.test(ua))             { os = "Windows"; }
    else if (/Mac OS X ([\d_]+)/.test(ua))      { os = "macOS";   osVersion = RegExp.$1.replace(/_/g,"."); }
    else if (/Android ([\d.]+)/.test(ua))        { os = "Android"; osVersion = RegExp.$1; }
    else if (/iPhone OS ([\d_]+)/.test(ua))      { os = "iOS";     osVersion = RegExp.$1.replace(/_/g,"."); }
    else if (/iPad.*OS ([\d_]+)/.test(ua))       { os = "iPadOS";  osVersion = RegExp.$1.replace(/_/g,"."); }
    else if (/Linux/.test(ua))                   { os = "Linux"; }

    // Device type
    const isMob = /Mobi|Android|iPhone|BlackBerry|IEMobile|Opera Mini/i.test(ua);
    const isTab = /iPad/i.test(ua) || (/Android/i.test(ua) && !/Mobile/i.test(ua));
    const deviceType = isTab ? "Tablet" : isMob ? "Mobile" : "Desktop";

    // Screen & locale info (safe — no permission needed)
    const screen   = `${window.screen?.width || "?"}×${window.screen?.height || "?"}`;
    const colorDep = window.screen?.colorDepth ? `${window.screen.colorDepth}-bit` : "";
    const lang     = navigator.language || navigator.userLanguage || "?";
    const tz       = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch { return "?"; } })();
    const memory   = navigator.deviceMemory ? `${navigator.deviceMemory} GB RAM` : "";
    const cores    = navigator.hardwareConcurrency ? `${navigator.hardwareConcurrency} cores` : "";
    const touch    = navigator.maxTouchPoints > 0 ? `touch(${navigator.maxTouchPoints})` : "no-touch";

    return {
      browser,
      browserVersion,
      os,
      osVersion,
      deviceType,
      screen,
      colorDep,
      lang,
      tz,
      memory,
      cores,
      touch,
      raw: ua
    };
  }

  // ─── Rate limiter (per-device, localStorage) ─────
  function getFailState() {
    try {
      const raw = localStorage.getItem(LS_FAILS);
      if (!raw) return { count: 0, firstAt: 0, lastAt: 0 };
      const obj = JSON.parse(raw);
      // Reset if window expired
      if (Date.now() - obj.firstAt > FAIL_WINDOW_MS) {
        localStorage.removeItem(LS_FAILS);
        return { count: 0, firstAt: 0, lastAt: 0 };
      }
      return obj;
    } catch { return { count: 0, firstAt: 0, lastAt: 0 }; }
  }

  function bumpFail() {
    const s = getFailState();
    const now = Date.now();
    const next = { count: s.count + 1, firstAt: s.firstAt || now, lastAt: now };
    localStorage.setItem(LS_FAILS, JSON.stringify(next));
    if (next.count >= MAX_FAILS) {
      const until = now + LOCKOUT_MS;
      localStorage.setItem(LS_BLOCKED_UNTIL, String(until));
    }
    return next;
  }

  function resetFails() {
    localStorage.removeItem(LS_FAILS);
    localStorage.removeItem(LS_BLOCKED_UNTIL);
  }

  function getBlockedUntil() {
    const v = parseInt(localStorage.getItem(LS_BLOCKED_UNTIL) || "0", 10);
    if (!v || isNaN(v)) return 0;
    if (Date.now() >= v) {
      localStorage.removeItem(LS_BLOCKED_UNTIL);
      localStorage.removeItem(LS_FAILS);
      return 0;
    }
    return v;
  }

  function isRateBlocked() { return getBlockedUntil() > 0; }

  // ─── Blocked IPs (localStorage cache + RTDB) ─────
  function getBlockedIPsCached() {
    try { return JSON.parse(localStorage.getItem(LS_BLOCKED_IPS) || "[]"); }
    catch { return []; }
  }
  function setBlockedIPsCache(list) {
    try { localStorage.setItem(LS_BLOCKED_IPS, JSON.stringify(list)); } catch {}
  }
  function isIPBlocked(ip) {
    if (!ip || ip === "unknown") return false;
    return getBlockedIPsCached().some(x => x.ip === ip);
  }
  async function syncBlockedIPsFromRTDB() {
    try {
      if (typeof db === "undefined" || !db) return;
      const snap = await get(ref(db, RTDB_BLOCKED));
      const v = snap.val() || {};
      const list = Object.keys(v).map(k => ({ ip: v[k].ip, blockedAt: v[k].blockedAt, reason: v[k].reason || "" }));
      setBlockedIPsCache(list);
      return list;
    } catch (e) { console.warn("[LoginSecurity] blockedIPs sync failed:", e.message); return getBlockedIPsCached(); }
  }
  async function blockIP(ip, reason) {
    if (!ip || ip === "unknown") return;
    const key = ip.replace(/[.:]/g, "_");
    const entry = { ip, blockedAt: Date.now(), reason: reason || "manual", addedBy: (auth && auth.currentUser && auth.currentUser.email) || "admin" };
    try { await update(ref(db, `${RTDB_BLOCKED}/${key}`), entry); } catch (e) { console.warn(e.message); }
    const cache = getBlockedIPsCached().filter(x => x.ip !== ip);
    cache.push({ ip, blockedAt: entry.blockedAt, reason: entry.reason });
    setBlockedIPsCache(cache);
    if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("warn", "security", `IP blocked: ${ip} (${entry.reason})`);
  }
  async function unblockIP(ip) {
    const key = ip.replace(/[.:]/g, "_");
    try { await remove(ref(db, `${RTDB_BLOCKED}/${key}`)); } catch (e) { console.warn(e.message); }
    setBlockedIPsCache(getBlockedIPsCached().filter(x => x.ip !== ip));
    if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("ok", "security", `IP unblocked: ${ip}`);
  }

  // ─── Login log ──────────────────────────────────
  function getLocalLogs() {
    try { return JSON.parse(localStorage.getItem(LS_LOGS_LOCAL) || "[]"); }
    catch { return []; }
  }
  function pushLocalLog(entry) {
    const list = getLocalLogs();
    list.unshift(entry);
    while (list.length > LOG_KEEP) list.pop();
    try { localStorage.setItem(LS_LOGS_LOCAL, JSON.stringify(list)); } catch {}
  }

  async function recordLogin(status, reason, extra) {
    const ipInfo = await getClientIP();
    const browser = getBrowserInfo();
    const entry = {
      ts: Date.now(),
      ip: ipInfo.ip,
      country: ipInfo.country,
      city: ipInfo.city,
      region: ipInfo.region,
      isp: ipInfo.isp,
      browser: browser.browser,
      browserVersion: browser.browserVersion,
      os: browser.os,
      osVersion: browser.osVersion,
      deviceType: browser.deviceType,
      screen: browser.screen,
      lang: browser.lang,
      tz: browser.tz,
      memory: browser.memory,
      cores: browser.cores,
      touch: browser.touch,
      deviceId: getDeviceId(),
      status: status || "unknown",
      reason: reason || "",
      ...(extra || {})
    };
    // Always to localStorage
    pushLocalLog(entry);
    // To RTDB — retry up to 3× (RTDB auth token may need a moment after signIn)
    if (auth && db) {
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          if (!auth.currentUser) break; // not authenticated at all
          const newRef = push(ref(db, RTDB_LOGS));
          await set(newRef, entry);
          await trimRemoteLogs();
          break; // success
        } catch (_) {
          if (attempt < 2) await new Promise(r => setTimeout(r, 600 * (attempt + 1)));
        }
      }
    }
    return entry;
  }

  // Sync any local-only logs to RTDB (called after login succeeds)
  async function syncLocalLogsToRTDB() {
    if (!auth || !auth.currentUser || !db) return;
    try {
      const local = getLocalLogs();
      if (!local.length) return;
      const snap = await get(ref(db, RTDB_LOGS));
      const remote = snap.val() || {};
      // Use ts+deviceId as dedup key (more reliable than ts+status+ip)
      const remoteKeys = new Set(
        Object.values(remote).map(e => `${e.ts}_${e.deviceId || e.ip}`)
      );
      for (const entry of local) {
        const k = `${entry.ts}_${entry.deviceId || entry.ip}`;
        if (!remoteKeys.has(k)) {
          await set(push(ref(db, RTDB_LOGS)), entry);
        }
      }
      await trimRemoteLogs();
    } catch (_) {}
  }

  async function trimRemoteLogs() {
    try {
      const snap = await get(ref(db, RTDB_LOGS));
      const v = snap.val() || {};
      const keys = Object.keys(v);
      if (keys.length <= LOG_KEEP) return;
      // Sort by ts descending, keep first LOG_KEEP
      const sorted = keys.map(k => ({ k, ts: v[k].ts || 0 })).sort((a,b) => b.ts - a.ts);
      const toRemove = sorted.slice(LOG_KEEP);
      for (const item of toRemove) {
        await remove(ref(db, `${RTDB_LOGS}/${item.k}`));
      }
    } catch (_) {}
  }

  async function getLogs(limit) {
    limit = limit || 10;
    let merged = getLocalLogs();
    try {
      if (auth && auth.currentUser && db) {
        const snap = await get(ref(db, RTDB_LOGS));
        const v = snap.val() || {};
        const remote = Object.keys(v).map(k => ({ _key: k, ...v[k] }));
        // Merge by timestamp (dedupe within 1s of same status+ip)
        const byKey = new Map();
        remote.forEach(e => byKey.set(`${e.ts}_${e.status}_${e.ip}`, e));
        merged.forEach(e => {
          const k = `${e.ts}_${e.status}_${e.ip}`;
          if (!byKey.has(k)) byKey.set(k, e);
        });
        merged = [...byKey.values()];
      }
    } catch (_) {}
    merged.sort((a,b) => (b.ts || 0) - (a.ts || 0));
    return merged.slice(0, limit);
  }

  async function clearAllLogs() {
    localStorage.removeItem(LS_LOGS_LOCAL);
    try {
      if (auth && auth.currentUser && db) await remove(ref(db, RTDB_LOGS));
    } catch (_) {}
  }

  // Reset _ipCache so a manual refresh actually re-fetches
  function refreshIPCache() { _ipCache = null; _ipFetched = false; }

  return {
    MAX_FAILS, LOCKOUT_MS,
    getClientIP, getBrowserInfo, getDeviceId,
    bumpFail, resetFails, getFailState, isRateBlocked, getBlockedUntil,
    blockIP, unblockIP, isIPBlocked, syncBlockedIPsFromRTDB, getBlockedIPsCached,
    recordLogin, syncLocalLogsToRTDB, getLogs, clearAllLogs,
    getLocalLogs,
    refreshIPCache
  };
})();

// ══════════════════════════════════════════════════════
// LOGIN UI HELPERS — rate-block screen + 2FA step
// ══════════════════════════════════════════════════════
let _rateBlockTimerId = null;
let _login2FATimerId  = null;
let _pendingLogin2FA  = false;

function showLoginRateBlock(until) {
  const form = document.getElementById("login-form");
  const fa   = document.getElementById("login-2fa-step");
  const blk  = document.getElementById("login-rate-block");
  if (form) form.classList.add("hidden");
  if (fa)   fa.classList.add("hidden");
  if (blk)  blk.classList.remove("hidden");
  const reason = document.getElementById("rate-block-reason");
  if (reason) reason.textContent = `${LoginSecurity.MAX_FAILS} failed attempts`;
  // Live countdown
  if (_rateBlockTimerId) clearInterval(_rateBlockTimerId);
  const tick = () => {
    const ms = until - Date.now();
    if (ms <= 0) {
      clearInterval(_rateBlockTimerId);
      _rateBlockTimerId = null;
      LoginSecurity.resetFails();
      // Reveal login form again
      if (blk)  blk.classList.add("hidden");
      if (form) form.classList.remove("hidden");
      if (typeof _generateCaptcha === "function") _generateCaptcha();
      return;
    }
    const m = Math.floor(ms / 60000);
    const s = Math.floor((ms % 60000) / 1000);
    const el = document.getElementById("rate-block-timer");
    if (el) el.textContent = `${String(m).padStart(2,"0")}:${String(s).padStart(2,"0")}`;
  };
  tick();
  _rateBlockTimerId = setInterval(tick, 1000);
}

function showLogin2FAStep() {
  const form = document.getElementById("login-form");
  const fa   = document.getElementById("login-2fa-step");
  const blk  = document.getElementById("login-rate-block");
  if (form) form.classList.add("hidden");
  if (blk)  blk.classList.add("hidden");
  if (fa)   fa.classList.remove("hidden");
  // Reset cells
  const cells = fa ? fa.querySelectorAll(".otp-cell") : [];
  cells.forEach(c => { c.value = ""; c.classList.remove("ok","bad"); });
  if (cells[0]) cells[0].focus();
  // Wire OTP cell auto-advance (idempotent)
  cells.forEach((cell, idx) => {
    if (cell._otpWired) return;
    cell._otpWired = true;
    cell.addEventListener("input", () => {
      cell.value = cell.value.replace(/[^0-9]/g, "");
      if (cell.value && cells[idx + 1]) cells[idx + 1].focus();
    });
    cell.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !cell.value && cells[idx - 1]) cells[idx - 1].focus();
      if (e.key === "Enter") {
        const code = [...cells].map(c => c.value).join("");
        if (code.length === 6) document.getElementById("login-2fa-btn").click();
      }
    });
    cell.addEventListener("paste", (e) => {
      const txt = (e.clipboardData || window.clipboardData).getData("text").replace(/\D/g, "");
      if (txt.length >= 6) {
        e.preventDefault();
        cells.forEach((c, i) => { c.value = txt[i] || ""; });
        cells[5].focus();
      }
    });
  });
  // Cancel button
  const cancelBtn = document.getElementById("login-2fa-cancel");
  if (cancelBtn && !cancelBtn._wired) {
    cancelBtn._wired = true;
    cancelBtn.addEventListener("click", () => {
      _pendingLogin2FA = false;
      // Sign out the partial Firebase session
      try { signOut(auth); } catch {}
      if (fa)   fa.classList.add("hidden");
      if (form) form.classList.remove("hidden");
      if (typeof _generateCaptcha === "function") _generateCaptcha();
    });
  }
  // Progress bar countdown
  if (_login2FATimerId) clearInterval(_login2FATimerId);
  const update = () => {
    const remain = getTOTPRemaining();
    const pct = (remain / 30) * 100;
    const bar = document.getElementById("login-2fa-progress-bar");
    const txt = document.getElementById("login-2fa-progress-txt");
    if (bar) {
      bar.style.width = pct + "%";
      bar.style.background = remain <= 5
        ? "linear-gradient(90deg,#ef4444,#dc2626)"
        : (remain <= 10 ? "linear-gradient(90deg,#f59e0b,#fbbf24)" : "linear-gradient(90deg,#34d399,#10b981)");
    }
    if (txt) txt.textContent = `${remain}s`;
  };
  update();
  _login2FATimerId = setInterval(update, 1000);
}

window.handleLogin2FA = async function(e) {
  e.preventDefault();
  const cells = document.querySelectorAll("#login-2fa-step .otp-cell");
  const code = [...cells].map(c => c.value).join("");
  const errEl = document.getElementById("login-2fa-error");
  const secret = window._settings.login_2fa_secret || "";
  if (code.length !== 6) {
    if (errEl) { errEl.textContent = "Enter all 6 digits."; errEl.classList.remove("hidden"); }
    return;
  }
  if (!secret) {
    if (errEl) { errEl.textContent = "2FA secret missing — disable from Settings."; errEl.classList.remove("hidden"); }
    return;
  }
  // Allow ±1 step (30s) drift for clock skew
  const expected = await generateTOTP(secret);
  let valid = (code === expected);
  if (!valid) {
    // try previous & next windows
    const counter = Math.floor(Date.now() / 1000 / 30);
    for (const off of [-1, 1]) {
      const t = (counter + off) * 30 * 1000;
      const prevDate = new Date(t);
      // Recompute manually:
      const c = await generateTOTPAt(secret, counter + off);
      if (c === code) { valid = true; break; }
    }
  }
  if (!valid) {
    cells.forEach(c => { c.classList.add("bad"); c.classList.remove("ok"); });
    setTimeout(() => cells.forEach(c => c.classList.remove("bad")), 600);
    if (errEl) { errEl.textContent = "Invalid code. Try again."; errEl.classList.remove("hidden"); }
    if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("warn", "security", "Login 2FA code rejected");
    LoginSecurity.bumpFail();
    LoginSecurity.recordLogin("2fa-fail", "Invalid TOTP code");
    // After enough fails the rate-block still applies on next attempt
    return;
  }
  cells.forEach(c => c.classList.add("ok"));
  if (errEl) errEl.classList.add("hidden");
  if (_login2FATimerId) { clearInterval(_login2FATimerId); _login2FATimerId = null; }
  _pendingLogin2FA = false;
  LoginSecurity.resetFails();
  await LoginSecurity.recordLogin("success", "Password + 2FA");
  await LoginSecurity.syncLocalLogsToRTDB();
  if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("ok", "security", "Login 2FA verified");
  showToast("Access granted. Welcome, Administrator.", "success");
  showPage("dashboard");
};

// Helper: TOTP at arbitrary counter (for drift tolerance)
async function generateTOTPAt(secret, counter) {
  try {
    const keyBytes = base32Decode(secret);
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    const high = Math.floor(counter / 0x100000000);
    const low = counter >>> 0;
    view.setUint32(0, high, false);
    view.setUint32(4, low, false);
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", key, buf);
    const hash = new Uint8Array(sig);
    const offset = hash[hash.length - 1] & 0x0f;
    const c = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
    return String(c % 1000000).padStart(6, "0");
  } catch { return "------"; }
}

window.handleLogin = async function(e) {
  e.preventDefault();
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  const errEl = document.getElementById("login-error");
  const btn = document.getElementById("login-btn");
  const capInp = document.getElementById("login-captcha");
  const capErr = document.getElementById("captcha-error");

  // ── ① Rate-limit gate (per-device) ──
  const blockedUntil = LoginSecurity.getBlockedUntil();
  if (blockedUntil > 0) {
    showLoginRateBlock(blockedUntil);
    if (typeof RealtimeLogger !== "undefined")
      RealtimeLogger.push("error", "security", `Login blocked — rate limit (until ${new Date(blockedUntil).toLocaleTimeString()})`);
    LoginSecurity.recordLogin("rate-limited", "Too many failed attempts");
    return;
  }

  // ── ② IP block gate ──
  const ipInfo = await LoginSecurity.getClientIP();
  if (LoginSecurity.isIPBlocked(ipInfo.ip)) {
    showLoginError(`Access denied. IP ${ipInfo.ip} is blocked.`);
    LoginSecurity.recordLogin("blocked", `IP ${ipInfo.ip} on block list`);
    if (typeof RealtimeLogger !== "undefined")
      RealtimeLogger.push("error", "security", `Login refused — IP ${ipInfo.ip} blocked`);
    return;
  }

  // ── ③ Captcha gate (always runs FIRST so bots that ignore the field fail) ──
  const ans = parseInt((capInp && capInp.value) || "", 10);
  window._captcha.attempts = (window._captcha.attempts || 0) + 1;
  if (isNaN(ans) || ans !== window._captcha.answer) {
    if (capInp) {
      capInp.classList.add("captcha-bad");
      capInp.classList.remove("captcha-ok");
      const wrap = document.querySelector(".captcha-wrap");
      if (wrap) { wrap.classList.remove("captcha-shake"); void wrap.offsetWidth; wrap.classList.add("captcha-shake"); }
    }
    if (capErr) {
      capErr.textContent = window._captcha.attempts >= 3
        ? "Too many wrong tries — new puzzle generated"
        : "Wrong answer — try again";
      capErr.classList.remove("hidden");
    }
    if (window._captcha.attempts >= 3) _generateCaptcha();
    if (typeof RealtimeLogger !== "undefined")
      RealtimeLogger.push("warn", "security", `Login captcha failed (attempt ${window._captcha.attempts})`);
    return;
  }

  if (typeof RealtimeLogger !== "undefined")
    RealtimeLogger.push("ok", "security", "Login captcha solved");

  if (username !== "admin") {
    showLoginError("Invalid username. Access denied.");
    _generateCaptcha();
    LoginSecurity.bumpFail();
    LoginSecurity.recordLogin("fail", "Invalid username");
    return;
  }

  btn.disabled = true;
  btn.innerHTML = `<span class="spinner" style="border-top-color:#fff;"></span> Authenticating...`;
  errEl.classList.add("hidden");

  // Pre-set flag so the onAuthStateChanged listener defers to us
  _pendingLogin2FA = true;
  try {
    await signInWithEmailAndPassword(auth, ADMIN_EMAIL, password);
    // Sync blocked-IP cache + settings now that we are authenticated
    await LoginSecurity.syncBlockedIPsFromRTDB();
    await loadAdminSettings();
    // ── Login 2FA gate ──
    if (window._settings.login_2fa_enabled === "1" && window._settings.login_2fa_secret) {
      // keep _pendingLogin2FA = true; 2FA panel will clear it on verify
      showLogin2FAStep();
      return;
    }
    _pendingLogin2FA = false;
    LoginSecurity.resetFails();
    await LoginSecurity.recordLogin("success", "Password only");
    await LoginSecurity.syncLocalLogsToRTDB();
    showToast("Access granted. Welcome, Administrator.", "success");
    if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("ok", "security", `🔓 Login successful — session started`);
    showPage("dashboard");
  } catch (err) {
    _pendingLogin2FA = false;
    let msg;
    if (err.code === "auth/invalid-credential" ||
        err.code === "auth/wrong-password" ||
        err.code === "auth/user-not-found") {
      // If user not found, try to create them (first-time setup recovery)
      if (err.code === "auth/user-not-found" || err.code === "auth/invalid-credential") {
        try {
          await createUserWithEmailAndPassword(auth, ADMIN_EMAIL, password);
          _pendingLogin2FA = false;
          LoginSecurity.resetFails();
          await LoginSecurity.recordLogin("success", "First-time admin init");
          await LoginSecurity.syncLocalLogsToRTDB();
          showToast("Admin account initialized. Welcome, Administrator.", "success");
          showPage("dashboard");
          return;
        } catch (createErr) {
          if (createErr.code === "auth/email-already-in-use") {
            msg = "Invalid credentials. Access denied.";
          } else if (createErr.code === "auth/operation-not-allowed") {
            msg = "Email/Password auth not enabled in Firebase Console. Enable it under Authentication → Sign-in method.";
          } else {
            msg = "Invalid credentials. Access denied.";
          }
        }
      } else {
        msg = "Invalid credentials. Access denied.";
      }
    } else if (err.code === "auth/too-many-requests") {
      msg = "Too many attempts. Try again later.";
    } else if (err.code === "auth/operation-not-allowed") {
      msg = "Email/Password auth not enabled in Firebase Console. Enable it under Authentication → Sign-in method.";
    } else if (err.code === "auth/network-request-failed") {
      msg = "Network error. Check your internet connection.";
    } else {
      msg = "Authentication failed: " + (err.code || err.message);
    }
    if (msg) {
      showLoginError(msg);
      // Count this as a failed attempt
      const next = LoginSecurity.bumpFail();
      LoginSecurity.recordLogin("fail", msg);
      if (next.count >= LoginSecurity.MAX_FAILS) {
        showLoginRateBlock(LoginSecurity.getBlockedUntil());
      }
    }
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Authenticate`;
  }
};

function showLoginError(msg) {
  const errEl = document.getElementById("login-error");
  errEl.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>${escHtml(String(msg||""))}`;
  errEl.classList.remove("hidden");
}

window.handleLogout = async function() {
  try {
    clearAllOTPIntervals();
    if (unsubscribeAccounts) {
      unsubscribeAccounts();
      unsubscribeAccounts = null;
    }
    if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("warn", "security", "🔒 Session ended — user signed out");
    await signOut(auth);
    allAccounts = [];
    _isFirstRender = true;
    document.getElementById("login-username").value = "";
    document.getElementById("login-password").value = "";
    document.getElementById("login-error").classList.add("hidden");
    showPage("login");
    showToast("Session terminated.", "info");
    VaultDebug.log("User logged out, state reset");
  } catch {}
};

// Auth state check on load
onAuthStateChanged(auth, async user => {
  if (user) {
    await loadAdminSettings();
    _weakAlertShown = false;
    hidePreloader();
    // ── If a fresh handleLogin is awaiting 2FA, do NOT jump to dashboard ──
    if (_pendingLogin2FA) return;
    // Sync block-list (best effort, non-blocking)
    LoginSecurity.syncBlockedIPsFromRTDB().catch(() => {});
    showPage("dashboard");
  } else {
    window._settings = {};
    if (unsubscribeAccounts) {
      unsubscribeAccounts();
      unsubscribeAccounts = null;
    }
    initAdmin();
  }
});

// ══════════════════════════════════════════════════════
// ACCOUNTS — FIRESTORE REAL-TIME LISTENER
// ══════════════════════════════════════════════════════
function showAccountsCyberLoader() {
  const loader = document.getElementById("accounts-cyber-loader");
  const grid = document.getElementById("accounts-grid");
  const statsBar = document.getElementById("stats-bar");
  const emptyState = document.getElementById("empty-state");
  if (loader) loader.classList.add("active");
  if (grid) grid.style.display = "none";
  if (statsBar) statsBar.classList.add("hidden");
  if (emptyState) emptyState.classList.add("hidden");
}

function hideAccountsCyberLoader() {
  const loader = document.getElementById("accounts-cyber-loader");
  const grid = document.getElementById("accounts-grid");
  if (loader) loader.classList.remove("active");
  if (grid) grid.style.display = "";
}

let _autoRecheckDone = false;
function setupAccountsListener() {
  if (unsubscribeAccounts) return;

  _isFirstRender = true;
  _autoRecheckDone = false;
  showAccountsCyberLoader();
  document.getElementById("accounts-grid").innerHTML = "";
  document.getElementById("stats-bar").classList.add("hidden");
  document.getElementById("empty-state").classList.add("hidden");

  const accountsRef = ref(db, ADMIN_COLLECTION);

  unsubscribeAccounts = onValue(accountsRef, (snap) => {
    const val = snap.val();
    if (val) {
      allAccounts = Object.entries(val)
        .map(([id, data]) => ({ id, ...data }))
        .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    } else {
      allAccounts = [];
    }
    VaultDebug.log("Firebase snapshot received:", allAccounts.length, "accounts");
    filterAccounts();

    if (typeof RealtimeLogger !== "undefined") {
      RealtimeLogger.push("ok", "firebase", `Snapshot received — ${allAccounts.length} account(s)`);
    }

    if (!_autoRecheckDone && allAccounts.length > 0) {
      _autoRecheckDone = true;
      setTimeout(() => {
        try { window.recheckAllAccounts({ silent: true }); }
        catch (e) { VaultDebug.error("Auto-recheck failed:", e.message); }
      }, 800);
    }
  }, (err) => {
    VaultDebug.error("RTDB error:", err.code, err.message);
    let msg = "Failed to load accounts.";
    if (err.code === "PERMISSION_DENIED") {
      msg = "Firebase Rules Error: Database → Rules এ set করো: { \"rules\": { \".read\": \"auth != null\", \".write\": \"auth != null\" } }";
    } else if (err.message) {
      msg = "Load error: " + err.message;
    }
    showToast(msg, "error");
    renderAccounts([]);
    unsubscribeAccounts = null;
  });
}

function renderAccounts(accounts = allAccounts) {
  clearAllOTPIntervals();
  hideAccountsCyberLoader();
  const grid = _dom.grid;
  const statsBar = _dom.statsBar;
  const emptyState = _dom.emptyState;

  grid.innerHTML = "";

  const total = accounts.length;
  const live = accounts.filter(a => a.status === "live").length;
  const dead = accounts.filter(a => a.status === "dead").length;

  const label = _dom.countLabel;
  if (label) label.textContent = `${total} account${total !== 1 ? "s" : ""} stored`;

  if (total === 0) {
    statsBar.classList.add("hidden");
    emptyState.classList.remove("hidden");
    const search = document.getElementById("search-input").value;
    const platform = document.getElementById("filter-platform").value;
    const status = document.getElementById("filter-status").value;
    if (search || platform || status) {
      document.getElementById("empty-title").textContent = "No matching accounts";
      document.getElementById("empty-desc").textContent = "Try adjusting your search or filter criteria.";
    } else {
      document.getElementById("empty-title").textContent = "No accounts yet";
      document.getElementById("empty-desc").textContent = 'Click "Add Account" to save your first account.';
    }
    return;
  }

  const curStatus = _dom.filterStatus?.value || "";
  statsBar.innerHTML = `
    <div class="stat-chip total ${curStatus === "" ? "active" : ""}" onclick="window._setStatusChip('')" title="Show all accounts" style="cursor:pointer;">
      <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
      Total: ${total}
    </div>
    <div class="stat-chip live ${curStatus === "live" ? "active" : ""}" onclick="window._setStatusChip('live')" title="Show live accounts" style="cursor:pointer;">
      <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>
      Live: ${live}
    </div>
    <div class="stat-chip dead ${curStatus === "dead" ? "active" : ""}" onclick="window._setStatusChip('dead')" title="Show dead accounts" style="cursor:pointer;">
      <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
      Dead: ${dead}
    </div>
  `;
  statsBar.classList.remove("hidden");
  emptyState.classList.add("hidden");

  // Sort: pinned first → live → dead → by createdAt desc
  const sorted = [...accounts].sort((a, b) => {
    const ap = _pinnedIds.has(a.id) ? 1 : 0;
    const bp = _pinnedIds.has(b.id) ? 1 : 0;
    if (bp !== ap) return bp - ap;
    const aLive = a.status !== "dead" ? 1 : 0;
    const bLive = b.status !== "dead" ? 1 : 0;
    if (bLive !== aLive) return bLive - aLive;
    return (b.createdAt || 0) - (a.createdAt || 0);
  });

  const frag = document.createDocumentFragment();
  sorted.forEach((account, idx) => {
    const card = buildAccountCard(account, idx);
    frag.appendChild(card);
  });
  grid.appendChild(frag);

  sorted.forEach(account => {
    if (account.twoFaKey) startOTPUpdater(account.id, account.twoFaKey);
  });

  _isFirstRender = false;
  VaultDebug.log(`Rendered ${total} accounts (live:${live} dead:${dead})`);
}

function getPlatformEmoji(platform) {
  const map = {
    facebook: "fb", instagram: "Ig", gmail: "Gm",
    twitter: "Tw", tiktok: "Tk", snapchat: "Sc",
    discord: "Dc", telegram: "Tg", whatsapp: "Wa",
    youtube: "Yt", linkedin: "Li", other: "??"
  };
  return map[platform] || "??";
}

function getPlatformLabel(platform) {
  const map = {
    facebook: "Facebook", instagram: "Instagram", gmail: "Gmail",
    twitter: "Twitter / X", tiktok: "TikTok", snapchat: "Snapchat",
    discord: "Discord", telegram: "Telegram", whatsapp: "WhatsApp",
    youtube: "YouTube", linkedin: "LinkedIn", other: "Other"
  };
  return map[platform] || "Other";
}

function maskPassword(pw) {
  if (!pw) return "—";
  return "•".repeat(Math.min(pw.length, 12));
}

const HEALTH_COLORS = {
  "📷": { bg: "rgba(96,165,250,0.08)",  color: "#60a5fa", border: "rgba(96,165,250,0.25)" },
  "📧": { bg: "rgba(74,222,128,0.08)",  color: "#4ade80", border: "rgba(74,222,128,0.25)" },
  "📱": { bg: "rgba(251,191,36,0.08)",  color: "#fbbf24", border: "rgba(251,191,36,0.25)" },
  "📅": { bg: "rgba(192,132,252,0.08)", color: "#c084fc", border: "rgba(192,132,252,0.25)" },
  "🔑": { bg: "rgba(248,113,113,0.08)", color: "#f87171", border: "rgba(248,113,113,0.25)" },
  "🔐": { bg: "rgba(251,146,60,0.08)",  color: "#fb923c", border: "rgba(251,146,60,0.25)" },
  "⚠️": { bg: "rgba(251,146,60,0.08)",  color: "#fb923c", border: "rgba(251,146,60,0.25)" },
  "🔴": { bg: "rgba(239,68,68,0.08)",   color: "#f87171", border: "rgba(239,68,68,0.25)" },
};

function _buildHealthPills(healthNoteStr) {
  if (!healthNoteStr) return "";
  const parts = healthNoteStr.split(" · ").filter(Boolean);
  const pills = parts.map(alert => {
    const emoji = alert.match(/^(📷|📧|📱|📅|🔑|🔐|⚠️|🔴)/u)?.[1] || "";
    const cfg = HEALTH_COLORS[emoji] || { bg: "rgba(245,158,11,0.08)", color: "#f59e0b", border: "rgba(245,158,11,0.25)" };
    return `<span class="health-pill" style="background:${cfg.bg};color:${cfg.color};border-color:${cfg.border};">${escHtml(alert.trim())}</span>`;
  }).join("");
  return `<div class="card-note-health">${pills}</div>`;
}

function buildAccountCard(account, idx = 0) {
  const div = document.createElement("div");
  const isPinned = _pinnedIds.has(account.id);
  const animClass = _isFirstRender ? " card-enter" : "";
  const isDead = account.status === "dead";
  div.className = `account-card status-${account.status || "live"}${isPinned ? " pinned" : ""}${animClass}`;
  if (_isFirstRender) div.style.animationDelay = `${Math.min(idx * 40, 400)}ms`;
  div.setAttribute("data-testid", `card-account-${account.id}`);
  div.setAttribute("data-platform", account.platform || "other");

  const hasImg = account.imageUrl && account.imageUrl.trim();
  const platformIcon = hasImg
    ? `<img src="${escHtml(account.imageUrl)}" class="platform-avatar" alt="${escHtml(account.name)}" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'" /><div class="platform-icon plat-${account.platform}" style="display:none">${getPlatformEmoji(account.platform)}</div>`
    : `<div class="platform-icon plat-${account.platform}">${getPlatformEmoji(account.platform)}</div>`;

  const otpSection = account.twoFaKey ? `
    <div class="otp-section">
      <div class="otp-header">
        <div class="otp-label">
          <svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
          2FA OTP
        </div>
        <div class="otp-timer">
          <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          <span id="otp-timer-${account.id}">30s</span>
        </div>
      </div>
      <div class="otp-code" id="otp-code-${account.id}" onclick="copyOTP('${account.id}')" title="Click to copy">
        <span>••• •••</span>
        <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      </div>
      <div class="otp-progress-bar">
        <div class="otp-progress-fill" id="otp-bar-${account.id}" style="width:100%"></div>
      </div>
    </div>
  ` : "";

  // — Custom note (user-written) shown separately
  const customNote = (account.note || "").trim();
  const customNoteHTML = customNote
    ? `<div class="card-note-custom">
        <span class="card-note-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </span>
        <span class="card-note-text">${escHtml(customNote)}</span>
       </div>`
    : "";

  // — Health note (auto-generated by recheck) shown as pills
  // Support both new `healthNote` field and old `note` field that has health emojis
  const legacyHealthInNote = account.note && (
    account.note.includes("📷") || account.note.includes("📧") || account.note.includes("📱") ||
    account.note.includes("📅") || account.note.includes("🔑") || account.note.includes("🔐") ||
    account.note.includes("⚠️") || account.note.includes("🔴")
  );
  const healthStr = account.healthNote || (legacyHealthInNote ? account.note : "");
  const healthPillsHTML = healthStr ? _buildHealthPills(healthStr) : "";

  // For legacy: if note had health content, don't show it again as custom note
  const showCustomNote = customNote && !legacyHealthInNote;

  div.innerHTML = `
    <div class="card-accent-bar"></div>
    <div class="card-header" onclick="openCardDetail('${account.id}')" style="cursor:pointer;" title="Click to view details">
      <div class="card-avatar-wrap">
        ${platformIcon}
        <span class="card-status-dot ${account.status || "live"}"></span>
      </div>
      <div class="card-title-area">
        <div class="card-name">${escHtml(account.name || "—")}</div>
        <div class="card-platform">${getPlatformLabel(account.platform)}</div>
        ${account.uid ? `<div class="card-uid mono">${escHtml(account.uid)}</div>` : ""}
      </div>
      <div class="card-header-right">
        <span class="status-badge ${account.status || "live"}">
          ${isDead ? "Dead" : "Live"}
        </span>
        ${isPinned ? `<span class="pin-badge-inline"><svg xmlns="http://www.w3.org/2000/svg" width="9" height="9" viewBox="0 0 24 24" fill="currentColor"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/></svg></span>` : ""}
      </div>
    </div>
    <div class="card-body" onclick="openCardDetail('${account.id}')" style="cursor:pointer;" title="Click to view details">
      ${account.email ? `<div class="info-row info-row-copy" onclick="event.stopPropagation();copyText('${escAttr(account.email)}','Email')" title="Copy email"><span class="info-label">Email</span><span class="info-value mono">${escHtml(account.email)}</span><span class="info-copy-icon"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></span></div>` : ""}
      ${account.number ? `<div class="info-row info-row-copy" onclick="event.stopPropagation();copyText('${escAttr(account.number)}','Phone')" title="Copy phone"><span class="info-label">Phone</span><span class="info-value mono">${escHtml(account.number)}</span><span class="info-copy-icon"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></span></div>` : ""}
      ${account.dob ? `<div class="info-row"><span class="info-label">DOB</span><span class="info-value mono">${escHtml(account.dob)}</span></div>` : ""}
      ${account.password ? `
        <div class="info-row">
          <span class="info-label">Password</span>
          <span class="info-value mono sensitive" id="pw-${account.id}">${maskPassword(account.password)}</span>
          <button class="btn-icon" onclick="event.stopPropagation();toggleRevealPassword('${account.id}','${escAttr(account.password)}')" title="Reveal/Hide password" style="margin-left:auto;">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
          <button class="btn-icon" onclick="event.stopPropagation();copyText('${escAttr(account.password)}','Password')" title="Copy password">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
      ` : ""}
      ${account.recoveryKey ? `
        <div class="info-row">
          <span class="info-label">Rec. Key</span>
          <span class="info-value mono sensitive">${"•".repeat(12)}</span>
          <button class="btn-icon" onclick="event.stopPropagation();copyText('${escAttr(account.recoveryKey)}','Recovery key')" title="Copy key" style="margin-left:auto;">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
      ` : ""}
      ${otpSection}
    </div>
    ${showCustomNote || healthPillsHTML ? `
    <div class="card-notes-area" onclick="openCardDetail('${account.id}')" style="cursor:pointer;">
      ${showCustomNote ? customNoteHTML : ""}
      ${healthPillsHTML}
    </div>` : ""}
    <div class="card-footer">
      <button class="btn-icon${isPinned ? " pin-active" : ""}" onclick="togglePin('${account.id}')" title="${isPinned ? "Unpin" : "Pin to top"}" data-testid="button-pin-${account.id}">
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="${isPinned ? "currentColor" : "none"}" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>
      </button>
      <div class="card-footer-spacer"></div>
      <button class="btn-icon" onclick="openEditModal('${account.id}')" title="Edit account" data-testid="button-edit-${account.id}">
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
      </button>
      <button class="btn-icon danger" onclick="confirmDelete('${account.id}')" title="Delete account" data-testid="button-delete-${account.id}">
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
      </button>
    </div>
  `;
  return div;
}

// ── OTP live updater ──
function startOTPUpdater(id, secret) {
  const update = async () => {
    const codeEl = document.getElementById(`otp-code-${id}`);
    const timerEl = document.getElementById(`otp-timer-${id}`);
    const barEl = document.getElementById(`otp-bar-${id}`);
    if (!codeEl) { clearInterval(otpIntervals[id]); return; }

    const otp = await generateTOTP(secret);
    const rem = getTOTPRemaining();
    const pct = getTOTPProgress();

    codeEl.innerHTML = `<span>${otp.slice(0, 3)} ${otp.slice(3)}</span>
      <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
    codeEl.setAttribute("data-otp", otp);
    if (timerEl) timerEl.textContent = rem + "s";
    if (barEl) {
      barEl.style.width = pct + "%";
      barEl.className = "otp-progress-fill" + (rem <= 5 ? " danger" : rem <= 10 ? " warning" : "");
    }
  };

  update();
  otpIntervals[id] = setInterval(update, 1000);
}

function clearAllOTPIntervals() {
  Object.values(otpIntervals).forEach(clearInterval);
  otpIntervals = {};
}

window.copyOTP = function(id) {
  const el = document.getElementById(`otp-code-${id}`);
  const otp = el?.getAttribute("data-otp");
  if (otp) copyText(otp, "OTP");
};

// ── PIN ACCOUNT ──
window.togglePin = function(id) {
  if (_pinnedIds.has(id)) {
    _pinnedIds.delete(id);
    showToast("Account unpinned.", "info");
  } else {
    _pinnedIds.add(id);
    showToast("Account pinned to top!", "success");
  }
  const pinned = JSON.stringify([..._pinnedIds]);
  localStorage.setItem("pinned_accounts", pinned);
  // Save to Firebase so all browsers sync
  update(ref(db, ADMIN_SETTINGS_PATH), { pinned_ids: pinned }).catch(() => {});
  filterAccounts();
};

// ── Filter / Search (debounced) ──
let _filterTimer = null;
function _doFilter() {
  const search = (_dom.searchInput?.value || "").toLowerCase();
  const platform = _dom.filterPlatform?.value || "";
  const status = _dom.filterStatus?.value || "";

  const clrBtn = document.getElementById("search-clear-btn");
  if (clrBtn) clrBtn.style.display = search ? "flex" : "none";

  const searchWrap = document.querySelector(".search-input-wrap.enhanced-search");
  if (searchWrap) searchWrap.classList.toggle("has-value", !!search);

  const filtered = allAccounts.filter(a => {
    const matchSearch = !search ||
      (a.name || "").toLowerCase().includes(search) ||
      (a.email || "").toLowerCase().includes(search) ||
      (a.uid || "").toLowerCase().includes(search) ||
      (a.number || "").toLowerCase().includes(search) ||
      (a.platform || "").toLowerCase().includes(search) ||
      (a.note || "").toLowerCase().includes(search);
    const matchPlatform = !platform || a.platform === platform;
    const matchStatus = !status || a.status === status;
    return matchSearch && matchPlatform && matchStatus;
  });

  renderAccounts(filtered);
}

window.filterAccounts = function() {
  clearTimeout(_filterTimer);
  _filterTimer = setTimeout(_doFilter, 180);
};

// Click a stat chip → set filter-status select + re-filter
window._setStatusChip = function(status) {
  const sel = _dom.filterStatus;
  if (sel) sel.value = status;
  _doFilter();
};

// ══════════════════════════════════════════════════════
// MODAL — ADD / EDIT
// ══════════════════════════════════════════════════════
window.openAddModal = function() {
  document.getElementById("account-id").value = "";
  document.getElementById("modal-title-text").textContent = "Add Account";
  document.getElementById("account-form").reset();
  openModal();
};

window.openEditModal = function(id) {
  const account = allAccounts.find(a => a.id === id);
  if (!account) return;
  document.getElementById("account-id").value = id;
  document.getElementById("modal-title-text").textContent = "Edit Account";
  document.getElementById("acc-platform").value = account.platform || "";
  document.getElementById("acc-name").value = account.name || "";
  document.getElementById("acc-uid").value = account.uid || "";
  document.getElementById("acc-email").value = account.email || "";
  document.getElementById("acc-number").value = account.number || "";
  document.getElementById("acc-dob").value = account.dob || "";
  document.getElementById("acc-password").value = account.password || "";
  document.getElementById("acc-2fa").value = account.twoFaKey || "";
  document.getElementById("acc-key").value = account.recoveryKey || "";
  document.getElementById("acc-img").value = account.imageUrl || "";
  document.getElementById("acc-status").value = account.status || "live";
  document.getElementById("acc-note").value = account.note || "";
  openModal();
};

window.handleSaveAccount = async function(e) {
  e.preventDefault();
  const saveBtn = document.getElementById("save-btn");
  saveBtn.disabled = true;
  saveBtn.innerHTML = `<span class="spinner" style="border-top-color:#fff;"></span> Saving...`;

  const id = document.getElementById("account-id").value;
  const rawNote = document.getElementById("acc-note").value.trim();
  const data = {
    platform: document.getElementById("acc-platform").value,
    name: document.getElementById("acc-name").value.trim(),
    uid: document.getElementById("acc-uid").value.trim(),
    email: document.getElementById("acc-email").value.trim(),
    number: document.getElementById("acc-number").value.trim(),
    dob: document.getElementById("acc-dob").value,
    password: document.getElementById("acc-password").value,
    twoFaKey: document.getElementById("acc-2fa").value.trim().replace(/\s/g, ""),
    recoveryKey: document.getElementById("acc-key").value.trim(),
    imageUrl: document.getElementById("acc-img").value.trim(),
    status: document.getElementById("acc-status").value,
    note: rawNote,
  };

  // Health note is generated separately — never overwrites user's custom note
  data.healthNote = generateHealthNote(data);

  // Warn if weak password
  if (isWeakPassword(data.password)) {
    showToast("⚠️ Weak password detected — consider using a stronger one.", "warning");
  }

  try {
    const now = Date.now();
    if (id) {
      const oldAcc = allAccounts.find(a => a.id === id);
      await update(ref(db, `${ADMIN_COLLECTION}/${id}`), { ...data, updatedAt: now });
      showToast("Account updated successfully.", "success");
      // Log edit — detect status change
      if (oldAcc && oldAcc.status !== data.status) {
        const logType = data.status === "dead" ? "status_dead" : "status_live";
        addVaultLog(logType, data.name || data.email, data.platform, `Status changed: ${oldAcc.status} → ${data.status}`);
        if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push(data.status === "dead" ? "warn" : "ok", "vault", `✏️ [${data.platform}] ${data.name || data.email} — status: ${oldAcc.status} → ${data.status}`);
      } else {
        addVaultLog("edited", data.name || data.email, data.platform, "Account info updated");
        if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("ok", "vault", `✏️ Edited [${data.platform}] ${data.name || data.email}`);
      }
    } else {
      await push(ref(db, ADMIN_COLLECTION), { ...data, createdAt: now, updatedAt: now });
      showToast("Account added successfully.", "success");
      addVaultLog("added", data.name || data.email, data.platform, `Added as ${data.status || "live"}`);
      if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("ok", "vault", `➕ Added [${data.platform}] ${data.name || data.email} (${data.status || "live"})`);
    }
    closeModal();
  } catch (err) {
    let msg = "Save failed.";
    if (err.code === "PERMISSION_DENIED") {
      msg = "Permission denied. Firebase Console → Realtime Database → Rules ঠিক করো।";
    } else if (err.message) {
      msg = "Save failed: " + err.message;
    }
    showToast(msg, "error");
  } finally {
    saveBtn.disabled = false;
    saveBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Save Account`;
  }
};

let _modalScrollY = 0;
function openModal() {
  _modalScrollY = window.scrollY || window.pageYOffset || 0;
  document.body.style.top      = `-${_modalScrollY}px`;
  document.body.style.position = "fixed";
  document.body.style.width    = "100%";
  document.getElementById("account-modal").classList.add("open");
}
window.closeModal = function() {
  document.getElementById("account-modal").classList.remove("open");
  document.body.style.position = "";
  document.body.style.top      = "";
  document.body.style.width    = "";
  window.scrollTo(0, _modalScrollY);
};
window.closeModalOnOverlay = function(e) {
  if (e.target.id === "account-modal") closeModal();
};

// ══════════════════════════════════════════════════════
// UID AUTO-FETCH  ·  Facebook link → UID + Name
// ══════════════════════════════════════════════════════
(function _wireUIDAutoFetch() {
  // API key lives in the backend — frontend only calls the local proxy route
  const UID_API = "/api/uid_find";
  let _debounceTimer = null;

  function _isFbLink(val) {
    return /facebook\.com|fb\.com|fb\.me/i.test(val.trim());
  }

  function _setUidFieldState(state, detail) {
    const field = document.getElementById("acc-uid");
    const hint  = document.getElementById("uid-fetch-hint");
    if (!field) return;
    if (state === "loading") {
      field.style.borderColor = "#3b82f6";
      if (hint) {
        hint.innerHTML   = "🔍 Looking up Facebook UID...";
        hint.style.color   = "#60a5fa";
        hint.style.display = "block";
      }
    } else if (state === "success") {
      field.style.borderColor = "#22c55e";
      if (hint) {
        hint.innerHTML   = "✅ Name and UID fetched successfully";
        hint.style.color   = "#4ade80";
        hint.style.display = "block";
        setTimeout(() => { if (hint) hint.style.display = "none"; }, 3500);
      }
    } else if (state === "error") {
      field.style.borderColor = "#ef4444";
      if (hint) {
        const msg = detail || "Could not fetch UID";
        hint.innerHTML = `❌ ${msg} — enter name manually <button class="uid-retry-btn" id="uid-retry-btn">↻ Retry</button>`;
        hint.style.color   = "#f87171";
        hint.style.display = "block";
        const retryBtn = document.getElementById("uid-retry-btn");
        if (retryBtn) {
          retryBtn.onclick = (e) => {
            e.preventDefault();
            const v = (document.getElementById("acc-uid") || {}).value || "";
            if (v.trim()) _fetchUID(v.trim());
          };
        }
      }
    } else {
      field.style.borderColor = "";
      if (hint) hint.style.display = "none";
    }
  }

  async function _fetchUID(fbLink) {
    _setUidFieldState("loading");
    try {
      const res = await fetch(UID_API, {
        method:  "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body:    "link=" + encodeURIComponent(fbLink),
        signal:  AbortSignal.timeout(25000)
      });

      const json = await res.json();

      // Backend returns { ok, uid, name, link } on success
      if (!json.ok) {
        const errMap = {
          "rate_limited":    "Too many requests — please wait a moment",
          "uid_not_found":   "UID not found for this profile",
          "link_required":   "No link provided",
          "timeout":         "Request timed out",
          "upstream_error":  "Upstream API error",
          "parse_error":     "Unexpected response from server"
        };
        throw new Error(errMap[json.error] || json.error || "UID fetch failed");
      }

      const uid  = String(json.uid  || "").trim() || null;
      const name = String(json.name || "").trim() || null;

      if (!uid) throw new Error("UID not found");

      const nameField = document.getElementById("acc-name");
      const noteField = document.getElementById("acc-note");

      // Link field: keep the original link as-is
      // Name field: auto-fill if empty
      if (nameField && !nameField.value.trim() && name) {
        nameField.value = name;
      }

      // Note box: show the numeric UID
      if (noteField) {
        const existing = noteField.value.trim();
        const uidLine  = "Facebook UID: " + uid;
        if (!existing) {
          noteField.value = uidLine;
        } else if (!existing.includes(uidLine)) {
          noteField.value = existing + "\n" + uidLine;
        }
      }

      // Auto-select platform if not already set
      const platField = document.getElementById("acc-platform");
      if (platField && !platField.value) platField.value = "facebook";

      _setUidFieldState("success");
      if (typeof showToast === "function") {
        showToast("UID found: " + uid + (name ? " · " + name : ""), "success");
      }

    } catch (err) {
      const msg = (err && err.name === "TimeoutError") ? "Request timed out"
                : (err && err.message) || "UID fetch failed";
      _setUidFieldState("error", msg);
      if (typeof showToast === "function") {
        showToast(msg + " — enter name manually", "warning");
      }
    }
  }

  function _injectHint() {
    const uidField = document.getElementById("acc-uid");
    if (!uidField || document.getElementById("uid-fetch-hint")) return;
    const hint = document.createElement("div");
    hint.id            = "uid-fetch-hint";
    hint.style.cssText = "display:none;font-size:11.5px;margin-top:5px;transition:color .2s;";
    uidField.parentNode.insertBefore(hint, uidField.nextSibling);
  }

  function _wireInput() {
    const uidField = document.getElementById("acc-uid");
    if (!uidField || uidField._uidWired) return;
    uidField._uidWired = true;
    _injectHint();

    uidField.addEventListener("input", () => {
      clearTimeout(_debounceTimer);
      const val = uidField.value.trim();
      _setUidFieldState("idle");
      if (!val || !_isFbLink(val)) return;
      _debounceTimer = setTimeout(() => _fetchUID(val), 700);
    });

    uidField.addEventListener("paste", () => {
      clearTimeout(_debounceTimer);
      // Let paste complete before reading value
      setTimeout(() => {
        const v = uidField.value.trim();
        if (_isFbLink(v)) _fetchUID(v);
      }, 80);
    });
  }

  // Re-wire every time the modal opens (Add or Edit)
  const _origOpenAdd = window.openAddModal;
  window.openAddModal = function() {
    if (_origOpenAdd) _origOpenAdd();
    setTimeout(_wireInput, 50);
  };

  const _origOpenEdit = window.openEditModal;
  window.openEditModal = function(id) {
    if (_origOpenEdit) _origOpenEdit(id);
    setTimeout(_wireInput, 50);
  };

  // Initial wire attempt (modal may already be in DOM)
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", _wireInput);
  } else {
    _wireInput();
  }
})();

// ══════════════════════════════════════════════════════
// DELETE
// ══════════════════════════════════════════════════════
window.confirmDelete = function(id) {
  deleteTargetId = id;
  document.getElementById("confirm-dialog").classList.add("open");
};
window.closeConfirm = function() {
  deleteTargetId = null;
  document.getElementById("confirm-dialog").classList.remove("open");
};
document.getElementById("confirm-delete-btn").addEventListener("click", async () => {
  if (!deleteTargetId) return;
  const btn = document.getElementById("confirm-delete-btn");
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner" style="border-top-color:#fff;"></span>`;
  const accToDelete = allAccounts.find(a => a.id === deleteTargetId);
  try {
    await remove(ref(db, `${ADMIN_COLLECTION}/${deleteTargetId}`));
    if (accToDelete) {
      addVaultLog("deleted", accToDelete.name || accToDelete.email, accToDelete.platform, `Deleted (was ${accToDelete.status || "live"})`);
      if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("warn", "vault", `🗑️ Deleted [${accToDelete.platform}] ${accToDelete.name || accToDelete.email} (was ${accToDelete.status || "live"})`);
    }
    showToast("Account deleted.", "info");
    closeConfirm();
  } catch (err) {
    showToast("Delete failed: " + err.message, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = "Delete";
  }
});

// ══════════════════════════════════════════════════════
// SETTINGS — CHANGE PASSWORD
// ══════════════════════════════════════════════════════
window.handleChangePassword = async function(e) {
  e.preventDefault();
  const current = document.getElementById("current-password").value;
  const newPw = document.getElementById("new-password").value;
  const confirm = document.getElementById("confirm-password").value;
  const alertEl = document.getElementById("pw-alert");
  const submitBtn = document.getElementById("pw-submit-btn");

  if (newPw !== confirm) {
    showPwAlert("New passwords do not match.", "error");
    return;
  }
  if (newPw.length < 8) {
    showPwAlert("Password must be at least 8 characters.", "error");
    return;
  }

  submitBtn.disabled = true;
  submitBtn.innerHTML = `<span class="spinner" style="border-top-color:#fff;"></span> Updating...`;
  alertEl.classList.add("hidden");

  try {
    // Wait for auth state to be confirmed (handles session restore timing)
    const user = await new Promise((resolve) => {
      if (auth.currentUser) { resolve(auth.currentUser); return; }
      const unsub = onAuthStateChanged(auth, (u) => { unsub(); resolve(u); });
    });
    if (!user) throw new Error("Session expired. Please log out and log in again.");
    const credential = EmailAuthProvider.credential(ADMIN_EMAIL, current);
    await reauthenticateWithCredential(user, credential);
    await updatePassword(user, newPw);
    showPwAlert("Password updated successfully.", "success");
    document.getElementById("current-password").value = "";
    document.getElementById("new-password").value = "";
    document.getElementById("confirm-password").value = "";
    showToast("Admin password changed.", "success");
  } catch (err) {
    const msg = err.code === "auth/invalid-credential" || err.code === "auth/wrong-password"
      ? "Current password is incorrect."
      : err.message;
    showPwAlert(msg, "error");
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Update Password`;
  }
};

function showPwAlert(msg, type) {
  const el = document.getElementById("pw-alert");
  el.className = `alert alert-${type}`;
  el.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>${escHtml(String(msg||""))}`;
  el.classList.remove("hidden");
}

function updateSettingsCount() {
  const el = document.getElementById("settings-total-count");
  if (el) el.textContent = allAccounts.length + " accounts";
  const exportEl = document.getElementById("settings-total-count-export");
  if (exportEl) exportEl.textContent = allAccounts.length;
}

// ══════════════════════════════════════════════════════
// DOWNLOAD ALL ACCOUNTS AS TXT  ·  Credit: RAIHAN
// ══════════════════════════════════════════════════════
window.downloadAccountsTxt = function() {
  if (!allAccounts.length) {
    showToast("No accounts to download.", "error");
    return;
  }

  const now = new Date();
  const dateStr = now.toLocaleDateString("en-BD", { year:"numeric", month:"long", day:"numeric" });
  const timeStr = now.toLocaleTimeString("en-BD", { hour:"2-digit", minute:"2-digit", second:"2-digit" });

  const sanitize = (val) => {
    if (!val) return "";
    return String(val).replace(/\r?\n|\r/g, " | ").replace(/\t/g, " ");
  };

  const DIVIDER  = "================================================";
  const DIVIDER2 = "------------------------------------------------";

  const lines = [];
  lines.push(DIVIDER);
  lines.push("   PRIVATE VAULT — ACCOUNT EXPORT");
  lines.push(DIVIDER);
  lines.push("  Date       : " + dateStr);
  lines.push("  Time       : " + timeStr);
  lines.push("  Total      : " + allAccounts.length + " account(s)");
  lines.push("  Credit     : RAIHAN");
  lines.push(DIVIDER);
  lines.push("");

  allAccounts.forEach((acc, idx) => {
    const num = String(idx + 1).padStart(2, "0");
    lines.push(`  [${num}]  ${sanitize(acc.name) || "Unnamed Account"}`);
    lines.push(DIVIDER2);
    lines.push("  Platform   : " + getPlatformLabel(acc.platform));
    lines.push("  Status     : " + (acc.status || "live").toUpperCase());
    if (acc.uid)         lines.push("  User ID    : " + sanitize(acc.uid));
    if (acc.email)       lines.push("  Email      : " + sanitize(acc.email));
    if (acc.number)      lines.push("  Phone      : " + sanitize(acc.number));
    if (acc.dob)         lines.push("  Birth Date : " + sanitize(acc.dob));
    if (acc.password)    lines.push("  Password   : " + sanitize(acc.password));
    if (acc.recoveryKey) lines.push("  Rec. Key   : " + sanitize(acc.recoveryKey));
    if (acc.twoFaKey)    lines.push("  2FA Secret : " + sanitize(acc.twoFaKey));
    if (acc.note)        lines.push("  Note       : " + sanitize(acc.note));
    if (acc.createdAt)   lines.push("  Created    : " + new Date(acc.createdAt).toLocaleString("en-BD"));
    lines.push("");
  });

  lines.push(DIVIDER);
  lines.push("  END OF FILE — Private Vault by RAIHAN");
  lines.push(DIVIDER);

  const BOM = "\uFEFF";
  const content = BOM + lines.join("\r\n");
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  const fname = "PrivateVault_" + now.getFullYear() +
    String(now.getMonth()+1).padStart(2,"0") +
    String(now.getDate()).padStart(2,"0") + "_" +
    String(now.getHours()).padStart(2,"0") +
    String(now.getMinutes()).padStart(2,"0") + ".txt";
  a.download = fname;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast("Downloaded " + allAccounts.length + " account(s) as TXT.", "success");
};

// ══════════════════════════════════════════════════════
// DOWNLOAD ALL ACCOUNTS AS JSON  ·  Credit: RAIHAN
// ══════════════════════════════════════════════════════
window.downloadAccountsJson = function() {
  if (!allAccounts.length) {
    showToast("No accounts to download.", "error");
    return;
  }

  const exportData = {
    app: "Private Vault",
    credit: "RAIHAN",
    exportedAt: new Date().toISOString(),
    total: allAccounts.length,
    accounts: allAccounts.map(acc => {
      const clean = {};
      const fields = [
        "platform","name","uid","email","number","dob",
        "password","twoFaKey","recoveryKey","imageUrl",
        "status","note","createdAt","updatedAt"
      ];
      fields.forEach(f => { if (acc[f] !== undefined && acc[f] !== null && acc[f] !== "") clean[f] = acc[f]; });
      return clean;
    })
  };

  const now2 = new Date();
  const fname2 = "PrivateVault_" + now2.getFullYear() +
    String(now2.getMonth()+1).padStart(2,"0") +
    String(now2.getDate()).padStart(2,"0") + "_" +
    String(now2.getHours()).padStart(2,"0") +
    String(now2.getMinutes()).padStart(2,"0") + ".json";
  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json;charset=utf-8" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = fname2;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast("Downloaded " + allAccounts.length + " account(s) as JSON.", "success");
  if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("ok", "vault", `📤 Exported ${allAccounts.length} account(s) → ${fname2}`);
};

// ══════════════════════════════════════════════════════
// IMPORT ACCOUNTS  ·  TXT or JSON file → Firebase
// ══════════════════════════════════════════════════════
let _importParsed = []; // [{data, dup}]
let _importFileMeta = null;

function _importSetAlert(type, msg) {
  const a = document.getElementById("import-alert");
  if (!a) return;
  if (!msg) { a.classList.add("hidden"); a.textContent = ""; return; }
  a.classList.remove("hidden");
  a.className = "alert alert-" + (type || "info");
  a.textContent = msg;
}

function _importAccountKey(a) {
  // Duplicate signature: prefer uid+platform, else email+platform, else name+platform
  const plat = (a.platform || "").toLowerCase().trim();
  if (a.uid && a.uid.trim())     return "uid:"   + a.uid.trim().toLowerCase()   + "|" + plat;
  if (a.email && a.email.trim()) return "email:" + a.email.trim().toLowerCase() + "|" + plat;
  if (a.name && a.name.trim())   return "name:"  + a.name.trim().toLowerCase()  + "|" + plat;
  return "rand:" + Math.random();
}

function _importParseJson(text) {
  let raw;
  try { raw = JSON.parse(text); }
  catch (e) { throw new Error("Invalid JSON: " + e.message); }
  let arr = [];
  if (Array.isArray(raw)) arr = raw;
  else if (raw && Array.isArray(raw.accounts)) arr = raw.accounts;
  else if (raw && typeof raw === "object")     arr = [raw];
  return arr.map(_importNormaliseAccount).filter(Boolean);
}

function _importParseTxt(text) {
  // Strip BOM and normalise newlines
  const clean = text.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n");
  const lines = clean.split("\n");
  const accounts = [];
  let cur = null;
  // Map of TXT label → account field
  const FIELD_MAP = {
    "platform":   "platform",
    "status":     "status",
    "user id":    "uid",
    "uid":        "uid",
    "email":      "email",
    "phone":      "number",
    "number":     "number",
    "birth date": "dob",
    "dob":        "dob",
    "password":   "password",
    "rec. key":   "recoveryKey",
    "recovery key":"recoveryKey",
    "2fa secret": "twoFaKey",
    "2fa":        "twoFaKey",
    "note":       "note",
    "created":    "createdAt",
    "name":       "name"
  };
  // Header pattern: "  [01]  Account name" — start a new account block
  const headerRe = /^\s*\[\s*\d+\s*\]\s+(.+?)\s*$/;
  // Field pattern: "  Label    : value"
  const fieldRe  = /^\s*([A-Za-z][A-Za-z0-9. ]{0,30})\s*:\s*(.*?)\s*$/;

  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (!ln.trim()) continue;
    if (/^[-=]{4,}$/.test(ln.trim())) continue; // divider
    const h = ln.match(headerRe);
    if (h) {
      if (cur) accounts.push(cur);
      cur = { name: h[1].trim() };
      continue;
    }
    const f = ln.match(fieldRe);
    if (f && cur) {
      const key = f[1].toLowerCase().trim();
      const val = f[2];
      const fld = FIELD_MAP[key];
      if (fld && val) {
        if (fld === "createdAt") {
          const t = Date.parse(val);
          cur.createdAt = isNaN(t) ? val : t;
        } else if (fld === "status") {
          cur.status = val.toLowerCase().includes("dead") ? "dead" : "live";
        } else {
          cur[fld] = val;
        }
      }
    }
  }
  if (cur) accounts.push(cur);
  return accounts.map(_importNormaliseAccount).filter(Boolean);
}

function _importNormaliseAccount(raw) {
  if (!raw || typeof raw !== "object") return null;
  // Need at least a platform OR a name/email to be useful
  const acc = {
    platform:    String(raw.platform    || "other").toLowerCase().trim(),
    name:        String(raw.name        || raw.email || raw.uid || "Unnamed").trim(),
    uid:         String(raw.uid         || "").trim(),
    email:       String(raw.email       || "").trim(),
    number:      String(raw.number      || raw.phone || "").trim(),
    dob:         String(raw.dob         || "").trim(),
    password:    String(raw.password    || "").trim(),
    twoFaKey:    String(raw.twoFaKey    || raw.totp || "").trim().replace(/\s+/g, ""),
    recoveryKey: String(raw.recoveryKey || raw.recovery || "").trim(),
    imageUrl:    String(raw.imageUrl    || "").trim(),
    note:        String(raw.note        || "").trim(),
    status:      (String(raw.status || "live").toLowerCase().includes("dead")) ? "dead" : "live"
  };
  if (raw.createdAt) {
    const t = typeof raw.createdAt === "number" ? raw.createdAt : Date.parse(raw.createdAt);
    if (!isNaN(t)) acc.createdAt = t;
  }
  // Drop empty rows
  if (!acc.name && !acc.uid && !acc.email) return null;
  return acc;
}

function _importRenderPreview() {
  const box = document.getElementById("import-preview");
  if (!box) return;
  if (!_importParsed.length) { box.style.display = "none"; box.innerHTML = ""; return; }
  const newOnes = _importParsed.filter(p => !p.dup).length;
  const dupOnes = _importParsed.filter(p =>  p.dup).length;
  const showRows = _importParsed.slice(0, 100);
  const moreCount = Math.max(0, _importParsed.length - showRows.length);
  box.innerHTML = `
    <div class="import-preview-stats">
      <div class="import-stat"><div class="import-stat-num">${_importParsed.length}</div><div class="import-stat-lbl">Found</div></div>
      <div class="import-stat ok"><div class="import-stat-num">${newOnes}</div><div class="import-stat-lbl">New</div></div>
      <div class="import-stat dup"><div class="import-stat-num">${dupOnes}</div><div class="import-stat-lbl">Duplicate</div></div>
      <div class="import-stat"><div class="import-stat-num">${(_importFileMeta && _importFileMeta.kind) || "—"}</div><div class="import-stat-lbl">Format</div></div>
    </div>
    <div class="import-preview-list">
      ${showRows.map((p, i) => `
        <div class="import-row">
          <span class="import-row-idx">${String(i+1).padStart(2,"0")}</span>
          <span class="import-row-name">${_escapeHTMLImport(p.data.name)} · <span style="color:var(--text3);">${_escapeHTMLImport(p.data.platform)}</span></span>
          <span class="import-row-tag ${p.dup ? "dup" : "new"}">${p.dup ? "Skip" : "New"}</span>
        </div>`).join("")}
      ${moreCount ? `<div style="text-align:center;color:var(--text3);font-size:11px;padding:6px;">+${moreCount} more…</div>` : ""}
    </div>
    <div class="import-progress" id="import-progress" style="display:none;"><div class="import-progress-bar" id="import-progress-bar"></div></div>
  `;
  box.style.display = "block";
}

function _escapeHTMLImport(s) {
  return String(s == null ? "" : s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

async function _importHandleFile(file) {
  if (!file) return;
  const dz = document.getElementById("import-dropzone");
  const nameEl = document.getElementById("import-file-name");
  const subEl  = document.getElementById("import-file-sub");
  const submitBtn = document.getElementById("import-submit-btn");
  const clearBtn  = document.getElementById("import-clear-btn");

  const isJson = /\.json$/i.test(file.name) || file.type === "application/json";
  const isTxt  = /\.txt$/i.test(file.name)  || file.type === "text/plain";
  if (!isJson && !isTxt) {
    _importSetAlert("error", "Only .txt and .json files are supported.");
    return;
  }

  let text;
  try { text = await file.text(); }
  catch (e) { _importSetAlert("error", "Could not read file: " + e.message); return; }

  let parsed = [];
  try {
    parsed = isJson ? _importParseJson(text) : _importParseTxt(text);
  } catch (e) {
    _importSetAlert("error", e.message);
    return;
  }

  if (!parsed.length) {
    _importSetAlert("warning", "No accounts found in the file. Make sure it was exported from Private Vault.");
    submitBtn.disabled = true;
    return;
  }

  // Build duplicate index from current vault
  const existing = new Set((window.allAccounts || []).map(_importAccountKey));
  const seen = new Set();
  _importParsed = parsed.map(d => {
    const k = _importAccountKey(d);
    const dup = existing.has(k) || seen.has(k);
    seen.add(k);
    return { data: d, dup };
  });
  _importFileMeta = { name: file.name, size: file.size, kind: isJson ? "JSON" : "TXT" };

  if (dz)     dz.classList.add("has-file");
  if (nameEl) nameEl.textContent = file.name;
  if (subEl)  subEl.textContent  = `${(file.size/1024).toFixed(1)} KB · ${_importFileMeta.kind} · ${_importParsed.length} account(s) found`;
  const newCount = _importParsed.filter(p => !p.dup).length;
  submitBtn.disabled = newCount === 0;
  submitBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg> Submit ${newCount} new account${newCount===1?"":"s"} to Firebase`;
  clearBtn.style.display = "inline-flex";
  _importSetAlert(null);
  _importRenderPreview();
}

window.clearImportFile = function() {
  _importParsed = [];
  _importFileMeta = null;
  const dz = document.getElementById("import-dropzone");
  const fileInput = document.getElementById("import-file-input");
  const nameEl = document.getElementById("import-file-name");
  const subEl  = document.getElementById("import-file-sub");
  const preview = document.getElementById("import-preview");
  const submitBtn = document.getElementById("import-submit-btn");
  const clearBtn  = document.getElementById("import-clear-btn");
  if (dz) dz.classList.remove("has-file");
  if (fileInput) fileInput.value = "";
  if (nameEl) nameEl.textContent = "Choose a .txt or .json file";
  if (subEl)  subEl.textContent  = "Click to browse or drag-and-drop here";
  if (preview) { preview.style.display = "none"; preview.innerHTML = ""; }
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg> Submit to Firebase`;
  }
  if (clearBtn) clearBtn.style.display = "none";
  _importSetAlert(null);
};

window.submitImportFile = async function() {
  const toImport = _importParsed.filter(p => !p.dup);
  if (!toImport.length) { _importSetAlert("warning", "Nothing new to import."); return; }
  if (typeof db === "undefined" || !db) {
    _importSetAlert("error", "Firebase not connected — please refresh and try again.");
    return;
  }
  const submitBtn = document.getElementById("import-submit-btn");
  const clearBtn  = document.getElementById("import-clear-btn");
  submitBtn.disabled = true;
  if (clearBtn) clearBtn.disabled = true;

  // Show progress bar
  const progress = document.getElementById("import-progress");
  const bar      = document.getElementById("import-progress-bar");
  if (progress) progress.style.display = "block";

  let saved = 0, failed = 0;
  const total = toImport.length;
  for (let i = 0; i < total; i++) {
    const a = toImport[i].data;
    const now = Date.now();
    const payload = {
      platform: a.platform || "other",
      name: a.name || "",
      uid: a.uid || "",
      email: a.email || "",
      number: a.number || "",
      dob: a.dob || "",
      password: a.password || "",
      twoFaKey: a.twoFaKey || "",
      recoveryKey: a.recoveryKey || "",
      imageUrl: a.imageUrl || "",
      status: a.status || "live",
      note: a.note || "",
      createdAt: a.createdAt || now,
      updatedAt: now
    };
    try {
      await push(ref(db, ADMIN_COLLECTION), payload);
      saved++;
    } catch (e) {
      failed++;
    }
    submitBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Importing… ${i+1}/${total}`;
    if (bar) bar.style.width = (((i+1)/total) * 100).toFixed(1) + "%";
  }

  if (saved > 0 && typeof addVaultLog === "function") {
    addVaultLog("bulk_added", `${saved} account(s)`, "other",
      `Imported from ${(_importFileMeta && _importFileMeta.name) || "file"}: ${saved} saved${failed ? ", " + failed + " failed" : ""}`);
    if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push(failed > 0 ? "warn" : "ok", "vault", `📥 Imported ${saved} account(s) from ${(_importFileMeta && _importFileMeta.name) || "file"}${failed ? ` (${failed} failed)` : ""}`);
  }

  if (failed === 0) {
    _importSetAlert("success", `Imported ${saved} account${saved===1?"":"s"} into Firebase.`);
    showToast(`Imported ${saved} account(s) successfully.`, "success");
  } else if (saved === 0) {
    _importSetAlert("error", `All ${failed} write(s) failed. Check Firebase rules and try again.`);
    showToast("Import failed.", "error");
  } else {
    _importSetAlert("warning", `Imported ${saved}, but ${failed} failed.`);
    showToast(`Imported ${saved}, ${failed} failed.`, "warning");
  }

  // Auto-clear after a moment so user sees the result
  setTimeout(() => { window.clearImportFile(); }, 1800);
  if (clearBtn) clearBtn.disabled = false;
};

// Wire up file input + drag-and-drop once the DOM is ready
function _wireImport() {
  const fileInput = document.getElementById("import-file-input");
  const dz = document.getElementById("import-dropzone");
  if (!fileInput || !dz || dz.dataset.bound === "1") return;
  dz.dataset.bound = "1";

  fileInput.addEventListener("change", e => {
    const f = e.target.files && e.target.files[0];
    if (f) _importHandleFile(f);
  });

  ["dragenter","dragover"].forEach(ev => dz.addEventListener(ev, e => {
    e.preventDefault(); e.stopPropagation();
    dz.classList.add("dragover");
  }));
  ["dragleave","drop"].forEach(ev => dz.addEventListener(ev, e => {
    e.preventDefault(); e.stopPropagation();
    dz.classList.remove("dragover");
  }));
  dz.addEventListener("drop", e => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) _importHandleFile(f);
  });
}
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", _wireImport);
} else {
  _wireImport();
}

// ══════════════════════════════════════════════════════
// SIDEBAR TOGGLE
// ══════════════════════════════════════════════════════
function isMobile() { return window.innerWidth <= 768; }

function setSidebarOverlay(sidebarId, show) {
  const overlay = document.getElementById("sidebar-overlay");
  if (overlay) overlay.classList.toggle("active", show);
}

window.toggleSidebar = function() {
  const sb = document.getElementById("sidebar");
  const willCollapse = !sb.classList.contains("collapsed");
  sb.classList.toggle("collapsed");
  if (isMobile()) setSidebarOverlay("sidebar", !willCollapse);
};

window.toggleSidebarSettings = function() {
  const sb = document.getElementById("sidebar-settings");
  const willCollapse = !sb.classList.contains("collapsed");
  sb.classList.toggle("collapsed");
  if (isMobile()) setSidebarOverlay("sidebar-settings", !willCollapse);
};

window.closeSidebar = function() {
  ["sidebar", "sidebar-settings"].forEach(id => {
    const sb = document.getElementById(id);
    if (sb) sb.classList.add("collapsed");
  });
  setSidebarOverlay(null, false);
};

// Auto-collapse sidebar on mobile on load
if (isMobile()) {
  ["sidebar", "sidebar-settings"].forEach(id => {
    const sb = document.getElementById(id);
    if (sb) sb.classList.add("collapsed");
  });
}

// ══════════════════════════════════════════════════════
// UTILITY
// ══════════════════════════════════════════════════════
window.togglePasswordVisibility = function(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const isPassword = input.type === "password";
  input.type = isPassword ? "text" : "password";
  btn.innerHTML = isPassword
    ? `<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
    : `<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
};

window.toggleRevealPassword = function(id, pw) {
  const el = document.getElementById(`pw-${id}`);
  if (!el) return;
  if (el.getAttribute("data-revealed") === "1") {
    el.textContent = maskPassword(pw);
    el.setAttribute("data-revealed", "0");
    el.className = "info-value mono sensitive";
  } else {
    el.textContent = pw;
    el.setAttribute("data-revealed", "1");
    el.className = "info-value mono";
    el.style.color = "var(--cyan)";
    setTimeout(() => {
      if (el.getAttribute("data-revealed") === "1") {
        el.textContent = maskPassword(pw);
        el.setAttribute("data-revealed", "0");
        el.className = "info-value mono sensitive";
        el.style.color = "";
      }
    }, 8000);
  }
};

window.copyText = function(text, label) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    showToast(`${label || "Text"} copied!`, "success");
  }).catch(() => {
    showToast("Copy failed. Please copy manually.", "error");
  });
};

function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escAttr(str) {
  if (!str) return "";
  return String(str)
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"');
}

// ══════════════════════════════════════════════════════
// TOAST
// ══════════════════════════════════════════════════════
function showToast(msg, type = "info", duration = 4000) {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const icons = {
    success: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
    error:   `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    info:    `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
    warning: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--yellow)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  };
  const toast = document.createElement("div");
  const toastType = icons[type] ? type : "info";
  toast.className = `toast ${toastType}`;
  toast.innerHTML = `${icons[toastType]}<span>${escHtml(msg)}</span>`;
  toast.onclick = () => toast.remove();
  container.appendChild(toast);
  const t = setTimeout(() => toast.remove(), duration);
  toast.addEventListener("click", () => clearTimeout(t), { once: true });
  if (type === "error") VaultDebug.error("Toast:", msg);
  else if (type === "warning") VaultDebug.warn("Toast:", msg);
}

// ══════════════════════════════════════════════════════
// ACCOUNT DETAIL POPUP
// ══════════════════════════════════════════════════════
let detailOTPInterval = null;

window.openCardDetail = function(id) {
  const account = allAccounts.find(a => a.id === id);
  if (!account) return;
  window._detailId = id;

  const body = document.getElementById("detail-body");
  body.innerHTML = buildDetailBody(account);

  document.getElementById("detail-modal").classList.add("open");
  document.body.style.overflow = "hidden";

  if (account.twoFaKey) startDetailOTP(id, account.twoFaKey);
};

window.closeDetail = function() {
  document.getElementById("detail-modal").classList.remove("open");
  document.body.style.overflow = "";
  if (detailOTPInterval) { clearInterval(detailOTPInterval); detailOTPInterval = null; }
};

window.closeDetailOnOverlay = function(e) {
  if (e.target.id === "detail-modal") closeDetail();
};

function buildDetailBody(account) {
  const hasImg = account.imageUrl && account.imageUrl.trim();
  const heroIcon = hasImg
    ? `<img src="${escHtml(account.imageUrl)}" class="detail-hero-img" alt="${escHtml(account.name)}" onerror="this.outerHTML='<div class=\\'detail-hero-icon plat-${account.platform}\\'>${getPlatformEmoji(account.platform)}</div>'" />`
    : `<div class="detail-hero-icon plat-${account.platform}">${getPlatformEmoji(account.platform)}</div>`;

  const statusBadge = `<span class="status-badge ${account.status || 'live'}" style="margin-top:6px;display:inline-flex;">
    <span class="status-dot-sm"></span>${account.status === 'dead' ? 'Dead' : 'Live'}
  </span>`;

  let rows = "";

  if (account.email) rows += detailRow("Email", account.email, account.email);
  if (account.number) rows += detailRow("Phone", account.number, account.number);
  if (account.uid) rows += detailRow("UID", account.uid, account.uid);
  if (account.dob) rows += detailRow("Date of Birth", account.dob, null);
  if (account.password) rows += detailPasswordRow(account);
  if (account.recoveryKey) rows += detailRow("Recovery Key", "•".repeat(Math.min(account.recoveryKey.length, 20)), account.recoveryKey);
  if (account.twoFaKey) rows += detailRow("2FA Key", "•".repeat(Math.min(account.twoFaKey.length, 20)), account.twoFaKey);

  const otpBox = account.twoFaKey ? `
    <div class="detail-otp-box">
      <div class="detail-otp-label">
        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
        Live 2FA OTP — click to copy
      </div>
      <div class="detail-otp-code" id="detail-otp-code-${account.id}" onclick="copyDetailOTP('${account.id}')" title="Click to copy">
        ••• •••
      </div>
      <div class="detail-otp-meta">
        <span class="detail-otp-timer" id="detail-otp-timer-${account.id}">30s</span>
        <div class="detail-otp-bar">
          <div class="detail-otp-fill" id="detail-otp-bar-${account.id}" style="width:100%"></div>
        </div>
      </div>
    </div>
  ` : "";

  const hasDetailAlert = account.note && (account.note.includes("⚠️") || account.note.includes("No 2FA") || account.note.includes("Weak password") || account.note.includes("📷") || account.note.includes("📧") || account.note.includes("📱") || account.note.includes("📅") || account.note.includes("🔑") || account.note.includes("🔐"));
  const noteBox = account.note ? `
    <div class="detail-note-box${hasDetailAlert ? " detail-note-alert" : ""}">${escHtml(account.note)}</div>
  ` : "";

  return `
    <div class="detail-hero">
      ${heroIcon}
      <div class="detail-hero-info">
        <div class="detail-hero-name">${escHtml(account.name || "—")}</div>
        <div class="detail-hero-platform">${getPlatformLabel(account.platform)}</div>
        ${account.uid ? `<div class="detail-hero-uid">${escHtml(account.uid)}</div>` : ""}
        ${statusBadge}
      </div>
    </div>
    ${otpBox}
    <div class="detail-rows">${rows}</div>
    ${noteBox}
  `;
}

function detailRow(label, display, copyValue) {
  const copyBtn = copyValue
    ? `<button class="btn-icon" onclick="copyText('${escAttr(copyValue)}','${escAttr(label)}')" title="Copy">
        <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      </button>` : "";
  return `
    <div class="detail-row">
      <span class="detail-row-label">${escHtml(label)}</span>
      <span class="detail-row-value">${escHtml(display)}</span>
      <div class="detail-row-actions">${copyBtn}</div>
    </div>`;
}

function detailPasswordRow(account) {
  return `
    <div class="detail-row">
      <span class="detail-row-label">Password</span>
      <span class="detail-row-value mono sensitive" id="detail-pw-${account.id}">${maskPassword(account.password)}</span>
      <div class="detail-row-actions">
        <button class="btn-icon" onclick="toggleDetailPw('${account.id}','${escAttr(account.password)}')" title="Reveal">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
        <button class="btn-icon" onclick="copyText('${escAttr(account.password)}','Password')" title="Copy">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        </button>
      </div>
    </div>`;
}

window.toggleDetailPw = function(id, pw) {
  const el = document.getElementById(`detail-pw-${id}`);
  if (!el) return;
  if (el.getAttribute("data-revealed") === "1") {
    el.textContent = maskPassword(pw);
    el.setAttribute("data-revealed", "0");
    el.style.color = "";
  } else {
    el.textContent = pw;
    el.setAttribute("data-revealed", "1");
    el.style.color = "var(--cyan)";
    setTimeout(() => {
      if (el.getAttribute("data-revealed") === "1") {
        el.textContent = maskPassword(pw);
        el.setAttribute("data-revealed", "0");
        el.style.color = "";
      }
    }, 8000);
  }
};

window.copyDetailOTP = function(id) {
  const el = document.getElementById(`detail-otp-code-${id}`);
  const otp = el?.getAttribute("data-otp");
  if (otp) copyText(otp, "OTP");
};

function startDetailOTP(id, secret) {
  const update = async () => {
    const codeEl = document.getElementById(`detail-otp-code-${id}`);
    const timerEl = document.getElementById(`detail-otp-timer-${id}`);
    const barEl = document.getElementById(`detail-otp-bar-${id}`);
    if (!codeEl) { clearInterval(detailOTPInterval); detailOTPInterval = null; return; }

    const otp = await generateTOTP(secret);
    const rem = getTOTPRemaining();
    const pct = getTOTPProgress();

    codeEl.textContent = otp.slice(0, 3) + " " + otp.slice(3);
    codeEl.setAttribute("data-otp", otp);
    if (timerEl) timerEl.textContent = rem + "s";
    if (barEl) {
      barEl.style.width = pct + "%";
      barEl.className = "detail-otp-fill" + (rem <= 5 ? " danger" : rem <= 10 ? " warning" : "");
    }
  };
  update();
  detailOTPInterval = setInterval(update, 1000);
}

// ══════════════════════════════════════════════════════
// IMGBB IMAGE UPLOAD
// ══════════════════════════════════════════════════════
window.handleImageUpload = async function(input) {
  const file = input.files[0];
  if (!file) return;

  const statusEl = document.getElementById("img-upload-status");
  statusEl.textContent = "Reading image...";
  statusEl.style.color = "var(--text3)";

  try {
    const base64 = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload  = () => resolve(reader.result.split(",")[1]);
      reader.onerror = () => reject(new Error("File read failed"));
      reader.readAsDataURL(file);
    });

    statusEl.textContent = "Uploading image...";
    const res = await fetch("/api/imgbb", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ image: base64, name: file.name || "upload", key: window._settings.imgbb_key || "" })
    });
    const json = await res.json();
    if (json.ok) {
      document.getElementById("acc-img").value = json.url;
      statusEl.textContent = "Upload successful!";
      statusEl.style.color = "var(--green)";
      setTimeout(() => { statusEl.textContent = ""; statusEl.style.color = ""; }, 3000);
    } else {
      statusEl.textContent = "Upload failed: " + (json.error || json.hint || "Unknown error");
      statusEl.style.color = "var(--red)";
    }
  } catch (err) {
    statusEl.textContent = "Upload error: " + err.message;
    statusEl.style.color = "var(--red)";
  }
  input.value = "";
};

// ══════════════════════════════════════════════════════
// API KEY STATE — Saved Display & Edit/Delete  ·  RAIHAN
// ══════════════════════════════════════════════════════

function maskKey(key) {
  if (!key) return "••••••••••••";
  const visible = key.slice(0, 8);
  const stars = "•".repeat(Math.min(key.length - 8, 12));
  return visible + stars;
}

window.showApiKeyState = function(type, key) {
  const hasKey = key && key.trim().length > 0;

  if (type === "imgbb") {
    const saved = document.getElementById("imgbb-key-saved");
    const form  = document.getElementById("imgbb-key-form");
    const masked = document.getElementById("imgbb-key-masked");
    if (!saved || !form) return;
    if (hasKey) {
      if (masked) masked.textContent = maskKey(key);
      saved.style.display = "block";
      form.style.display  = "none";
    } else {
      saved.style.display = "none";
      form.style.display  = "block";
    }
  } else if (type === "openai") {
    const saved = document.getElementById("openai-key-saved");
    const form  = document.getElementById("openai-key-form");
    const masked = document.getElementById("openai-key-masked");
    if (!saved || !form) return;
    if (hasKey) {
      if (masked) masked.textContent = maskKey(key);
      saved.style.display = "block";
      form.style.display  = "none";
    } else {
      saved.style.display = "none";
      form.style.display  = "block";
    }
  } else if (type === "gemini") {
    const saved = document.getElementById("gemini-key-saved");
    const form  = document.getElementById("gemini-key-form");
    const masked = document.getElementById("gemini-key-masked");
    if (!saved || !form) return;
    if (hasKey) {
      if (masked) masked.textContent = maskKey(key);
      saved.style.display = "block";
      form.style.display  = "none";
    } else {
      saved.style.display = "none";
      form.style.display  = "block";
    }
  }
};

window.editApiKey = function(type) {
  if (type === "imgbb") {
    document.getElementById("imgbb-key-saved").style.display = "none";
    document.getElementById("imgbb-key-form").style.display = "block";
    const el = document.getElementById("imgbb-api-key");
    if (el) { el.value = window._settings.imgbb_key || ""; el.focus(); }
  } else if (type === "openai") {
    document.getElementById("openai-key-saved").style.display = "none";
    document.getElementById("openai-key-form").style.display = "block";
    const el = document.getElementById("openai-api-key");
    if (el) { el.value = window._settings.openai_key || ""; el.focus(); }
  } else if (type === "gemini") {
    document.getElementById("gemini-key-saved").style.display = "none";
    document.getElementById("gemini-key-form").style.display = "block";
    const el = document.getElementById("gemini-api-key");
    if (el) { el.value = window._settings.gemini_key || ""; el.focus(); }
  }
};

window.deleteApiKey = async function(type) {
  const labels = { imgbb: "ImgBB", openai: "OpenAI", gemini: "Gemini" };
  const label = labels[type] || type;
  if (!confirm(`Delete saved ${label} API key from Firebase?`)) return;
  const settingKeys = { imgbb: "imgbb_key", openai: "openai_key", gemini: "gemini_key" };
  await saveSetting(settingKeys[type], "");
  window._settings[settingKeys[type]] = "";
  showApiKeyState(type, "");
  showToast(`${label} API key deleted.`, "info");
};

// ══════════════════════════════════════════════════════
// ACCOUNT RECHECK — Smart Health Scan  ·  Credit: _RAIHAN
// ══════════════════════════════════════════════════════

const WEAK_PASSWORDS = ["password","123456","123456789","12345678","12345","1234567","qwerty","abc123","111111","password1","iloveyou","admin","welcome","login","pass","letmein","monkey","1234","sunshine","princess","master","hello","freedom","whatever","qazwsx","trustno1","000000","654321","michael","superman"];

// Local fallback — backend `/api/password-check` is the source of truth
// but this lets the UI stay responsive (and work offline).
function isWeakPassword(pw) {
  if (!pw) return true;
  if (pw.length < 8) return true;
  if (WEAK_PASSWORDS.includes(pw.toLowerCase())) return true;
  if (/^(.)\1+$/.test(pw)) return true;
  if (/^(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)/.test(pw)) return true;
  return false;
}

// ── Thin backend client (centralises every /api/* call) ──
window.APP_VERSION = "10.A1.A2";
window.apiClient = (function () {
  const base = "/api";
  async function call(path, opts = {}) {
    const url = base + path + (opts.query ? "?" + new URLSearchParams(opts.query).toString() : "");
    const init = { method: opts.method || "GET", headers: { "Accept": "application/json" } };
    if (opts.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body);
    }
    const r = await fetch(url, init);
    let data = null;
    try { data = await r.json(); } catch (_) {}
    return { ok: r.ok, status: r.status, data };
  }
  return {
    health:        ()    => call("/health"),
    healthTxt:     ()    => fetch(base + "/health?format=txt").then(r => r.text()),
    version:       ()    => call("/version"),
    watchdog:      ()    => call("/watchdog"),
    check:         ()    => call("/check"),
    config:        ()    => call("/config"),
    analyze:       (accs)   => call("/analyze",       { method: "POST", body: { accounts: accs } }),
    passwordCheck: (pw)     => call("/password-check",{ method: "POST", body: { password: pw } }),
    totp:          (secret) => call("/totp",           { method: "POST", body: { secret } }),
    fbLive:        (uid)    => call("/fb-live",        { method: "POST", body: { uid } }),
  };
})();


// ── Real-time login logs listener (Settings page) ─────
let _loginLogsUnsub = null;
function _setupLoginLogsListener() {
  _teardownLoginLogsListener();
  if (!db || !auth || !auth.currentUser) {
    // No Firebase — show local logs only
    if (typeof renderLoginLogList === "function") renderLoginLogList();
    return;
  }
  // onValue passes snapshot directly → no second get() call → no loop
  _loginLogsUnsub = onValue(ref(db, "loginLogs"), (snap) => {
    if (typeof renderLoginLogList === "function") renderLoginLogList(snap);
  });
}
function _teardownLoginLogsListener() {
  if (_loginLogsUnsub) { _loginLogsUnsub(); _loginLogsUnsub = null; }
}

// ── Facebook Live Checker ──────────────────────────────
function extractFacebookUID(raw) {
  if (!raw || !raw.trim()) return null;
  let uid = raw.trim();
  // Handle uid|token format
  uid = uid.split("|")[0].trim();
  // Handle full Facebook URLs
  try {
    const url = new URL(uid);
    // profile.php?id=XXXXXXX
    const idParam = url.searchParams.get("id");
    if (idParam) return idParam.trim();
    // facebook.com/username  or  facebook.com/profile/username
    const parts = url.pathname.replace(/\/+$/, "").split("/").filter(Boolean);
    if (parts.length > 0) {
      const last = parts[parts.length - 1];
      if (last && last !== "profile" && last !== "www.facebook.com") return last;
    }
  } catch (_) {
    // Not a URL — return as-is (raw UID or username)
  }
  return uid || null;
}

// Returns true if a string looks like a pure numeric FB UID
function _isNumericUID(str) {
  return /^\d{8,20}$/.test((str || "").trim());
}

// Extract a numeric UID (or pipe-format UID) from a text block (note field)
function _extractNumericFromText(text) {
  if (!text) return null;
  // pipe-format: 1234567890|EAA...
  const pipeMatch = text.match(/\b(\d{8,20})\|[A-Za-z0-9_-]+/);
  if (pipeMatch) return pipeMatch[1];
  // bare numeric UID
  const numMatch = text.match(/\b(\d{8,20})\b/);
  if (numMatch) return numMatch[1];
  return null;
}

// Returns the best UID string to pass to checkFacebookUIDLive():
//   Priority: numeric UID from uid field > numeric UID from note > username/URL from uid field
// Special case: if uid field has a username URL (non-numeric), prefer note's numeric UID first
function getCheckableUID(account) {
  const rawUID  = (account.uid  || "").trim();
  const note    = (account.note || "").trim();

  // Resolve whatever is in the uid field (URL → username/id, pipe → left part)
  const resolvedUID = rawUID ? extractFacebookUID(rawUID) : null;

  // Is the resolved UID already a pure numeric FB ID?
  if (resolvedUID && _isNumericUID(resolvedUID)) return resolvedUID;

  // uid field has a username (non-numeric) or is empty — try note for a numeric UID first
  const numericFromNote = _extractNumericFromText(note);
  if (numericFromNote) return numericFromNote;

  // Fallback: use whatever was in uid field (username, URL) — graph API accepts usernames too
  if (resolvedUID) return resolvedUID;

  // uid field empty, note has no numeric — try a FB URL in the note as last resort
  const urlMatch = note.match(/https?:\/\/(?:www\.)?facebook\.com\/\S+/i);
  if (urlMatch) return urlMatch[0].trim();

  return null;
}

async function checkFacebookUIDLive(rawUID) {
  const uid = extractFacebookUID(rawUID);
  if (!uid) return null;
  try {
    // Use server-side proxy (/api/fb-live) to avoid CORS and expose no key
    const res = await fetch("/api/fb-live", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ uid })
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (!data || !data.ok) return null;
    return data.live; // true | false | null
  } catch (_) {
    // Fallback: try direct graph API if server proxy unreachable
    try {
      const r2 = await fetch(`https://graph.facebook.com/${encodeURIComponent(uid)}/picture?redirect=false`);
      if (!r2.ok) return false;
      const d2 = await r2.json();
      return !!(d2 && d2.data && d2.data.height);
    } catch (_2) {
      return null;
    }
  }
}

window.recheckAllAccounts = async function(opts = {}) {
  const silent = !!opts.silent;
  const btn   = document.getElementById("btn-recheck");
  const icon  = document.getElementById("recheck-icon");
  const label = document.getElementById("recheck-label");
  const RL    = (typeof RealtimeLogger !== "undefined") ? RealtimeLogger : null;

  if (!allAccounts || allAccounts.length === 0) {
    if (!silent) showToast("No accounts to check.", "info");
    if (RL) RL.push("info", "recheck", "No accounts to check");
    return;
  }

  if (RL) RL.push("info", "recheck", `Recheck started (${silent ? "auto" : "manual"}) — ${allAccounts.length} account(s)`);

  if (btn && !silent) btn.disabled = true;
  if (icon && !silent) icon.style.animation = "spin 1s linear infinite";
  if (label && !silent) label.textContent = "Checking...";

  let updatedCount = 0;

  // ── Separate FB accounts that need live check ──
  // Includes accounts with UID in uid field OR extractable from note field
  const fbAccounts = allAccounts.filter(a => a.platform === "facebook" && getCheckableUID(a));

  const fbLiveMap = {};
  const batchSize = 50;
  if (fbAccounts.length > 0) {
    if (label) label.textContent = "FB Live Check...";
    if (RL) RL.push("info", "recheck", `Live check: ${fbAccounts.length} FB account(s)`);
    for (let i = 0; i < fbAccounts.length; i += batchSize) {
      const batch = fbAccounts.slice(i, i + batchSize);
      await Promise.all(batch.map(async acc => {
        const checkUID = getCheckableUID(acc);
        fbLiveMap[acc.id] = await checkFacebookUIDLive(checkUID);
        const live = fbLiveMap[acc.id];
        const uidSource = (acc.uid && acc.uid.trim()) ? "uid" : "note";
        if (RL) RL.push(
          live === true ? "ok" : live === false ? "warn" : "info",
          "recheck",
          `UID ${checkUID} [from ${uidSource}] (${acc.name || "?"}) — ${live === true ? "✅ Live" : live === false ? "❌ Dead" : "⚠️ Check failed"}`
        );
      }));
    }
  }

  if (label) label.textContent = "Updating...";

  for (const account of allAccounts) {
    let newHealthNote = "";
    let newStatus = account.status;

    const isFBWithUID = account.platform === "facebook" && !!getCheckableUID(account);
    const uidSrc      = isFBWithUID ? ((account.uid && account.uid.trim()) ? "uid" : "note") : "";
    const fbLive = isFBWithUID ? fbLiveMap[account.id] : null;

    if (isFBWithUID && fbLive !== null) {
      newStatus = fbLive ? "live" : "dead";
    }

    if (newStatus === "dead") {
      const fbTag = isFBWithUID && fbLive !== null
        ? (fbLive ? " · ✅ FB Live" : ` · ❌ FB Dead [${uidSrc}]`) : "";
      newHealthNote = "🔴 Account marked as dead" + fbTag;
    } else {
      const alerts = [];
      if (isFBWithUID && fbLive !== null) {
        alerts.push(fbLive ? `✅ FB Live Confirmed [${uidSrc}]` : `❌ FB UID Dead [${uidSrc}]`);
      } else if (isFBWithUID && fbLive === null) {
        alerts.push("⚠️ FB Live Check Failed");
      }
      if (!account.imageUrl || !account.imageUrl.trim()) alerts.push("📷 No profile photo");
      if (!account.email   || !account.email.trim())    alerts.push("📧 No email linked");
      if (!account.number  || !account.number.trim())   alerts.push("📱 No phone number");
      if (!account.dob     || !account.dob.trim())      alerts.push("📅 No date of birth");
      if (!account.password|| !account.password.trim()) alerts.push("🔑 No password saved");
      else if (isWeakPassword(account.password))         alerts.push("⚠️ Weak password");
      if (!account.twoFaKey|| !account.twoFaKey.trim()) alerts.push("🔐 No 2FA set");
      newHealthNote = alerts.join(" · ");
    }

    const statusChanged = newStatus !== (account.status || "live");
    const healthChanged = newHealthNote !== (account.healthNote || "");

    if (statusChanged || healthChanged) {
      try {
        const updateData = { healthNote: newHealthNote };
        if (statusChanged) updateData.status = newStatus;
        await update(ref(db, `${ADMIN_COLLECTION}/${account.id}`), updateData);
        account.healthNote = newHealthNote;
        if (statusChanged) {
          account.status = newStatus;
          const logType = newStatus === "dead" ? "status_dead" : "status_live";
          addVaultLog(logType, account.name || account.email, account.platform,
            `Recheck: auto-${newStatus} (FB live check)`);
          if (RL) RL.push(newStatus === "dead" ? "warn" : "ok", "recheck",
            `Status changed → ${newStatus.toUpperCase()}: ${account.name || account.uid}`);
        }
        updatedCount++;
      } catch (err) {
        VaultDebug.error("Recheck update failed:", account.id, err.message);
        if (RL) RL.push("error", "recheck", `Update failed [${account.name}]: ${err.message}`);
      }
    }
  }

  // ── Done ──
  if (updatedCount > 0) {
    addVaultLog("recheck", "System", "system",
      `Recheck scanned ${allAccounts.length} account(s), ${updatedCount} updated`);
  }

  if (RL) RL.push(
    updatedCount > 0 ? "warn" : "ok",
    "recheck",
    `✅ Recheck finished — ${updatedCount} updated of ${allAccounts.length}`
  );

  if (btn)  btn.disabled = false;
  if (icon) icon.style.animation = "";
  if (label) label.textContent = "Recheck";

  filterAccounts();
  if (silent) return;
  if (updatedCount > 0) {
    showToast(`Recheck complete — ${updatedCount} account(s) updated.`, "success");
  } else {
    showToast("Recheck complete — all accounts are up to date.", "info");
  }
};

// ══════════════════════════════════════════════════════
// FIREBASE STATUS PANEL  ·  Credit: RAIHAN
// ══════════════════════════════════════════════════════

window.showFirebaseStatus = async function() {
  if (isMobile()) closeSidebar();
  const existing = document.getElementById("sc-overlay");
  if (existing) { existing.remove(); return; }

  const rulesJson = JSON.stringify({
    rules: {
      ".read": false,
      ".write": false,
      accounts: {
        ".read": "auth != null && auth.token.email === '" + ADMIN_EMAIL + "'",
        ".write": "auth != null && auth.token.email === '" + ADMIN_EMAIL + "'",
        "$accountId": {
          ".validate": "newData.hasChildren(['platform','name','status']) && newData.child('platform').isString() && newData.child('name').isString() && newData.child('status').isString()"
        }
      },
      admin_config: {
        ".read": "auth != null && auth.token.email === '" + ADMIN_EMAIL + "'",
        ".write": "auth != null && auth.token.email === '" + ADMIN_EMAIL + "'"
      },
      admin_settings: {
        ".read": "auth != null && auth.token.email === '" + ADMIN_EMAIL + "'",
        ".write": "auth != null && auth.token.email === '" + ADMIN_EMAIL + "'"
      },
      api_keys: {
        ".read": "auth != null && auth.token.email === '" + ADMIN_EMAIL + "'",
        ".write": "auth != null && auth.token.email === '" + ADMIN_EMAIL + "'",
        "$keyIndex": {
          ".validate": "newData.hasChildren(['label','key']) && newData.child('label').isString() && newData.child('label').val().length <= 100 && newData.child('key').isString()"
        }
      },
      vault_logs: {
        ".read": "auth != null && auth.token.email === '" + ADMIN_EMAIL + "'",
        ".write": "auth != null && auth.token.email === '" + ADMIN_EMAIL + "'",
        "$logId": {
          ".validate": "newData.hasChildren(['type','timestamp']) && newData.child('type').isString() && newData.child('timestamp').isNumber()"
        }
      },
      loginLogs: {
        ".read": "auth != null && auth.token.email === '" + ADMIN_EMAIL + "'",
        ".write": "auth != null && auth.token.email === '" + ADMIN_EMAIL + "'",
        "$logId": {
          ".validate": "newData.hasChildren(['ts','status']) && newData.child('ts').isNumber() && newData.child('status').isString()"
        }
      }
    }
  }, null, 2);

  const spinner = `<span class="sc-spinner"></span>`;
  const now = new Date().toLocaleString();

  const overlay = document.createElement("div");
  overlay.id = "sc-overlay";
  overlay.className = "sc-overlay";
  overlay.innerHTML = `
    <div class="sc-modal">

      <!-- Header -->
      <div class="sc-header">
        <div class="sc-header-left">
          <div class="sc-header-icon">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
          </div>
          <div>
            <div class="sc-header-title">System Status Check</div>
            <div class="sc-header-sub">Last checked: ${now}</div>
          </div>
        </div>
        <button class="sc-close-btn" onclick="document.getElementById('sc-overlay').remove()">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>

      <!-- Stat Cards -->
      <div class="sc-stats">
        <div class="sc-stat-card blue">
          <div class="sc-stat-icon">🔗</div>
          <div class="sc-stat-label">Connection</div>
          <div class="sc-stat-value" id="sc-conn-val">${spinner}</div>
          <div class="sc-stat-sub">Firebase RTDB</div>
        </div>
        <div class="sc-stat-card green">
          <div class="sc-stat-icon">👤</div>
          <div class="sc-stat-label">Accounts</div>
          <div class="sc-stat-value" id="sc-acc-val">${spinner}</div>
          <div class="sc-stat-sub">Total stored</div>
        </div>
        <div class="sc-stat-card yellow">
          <div class="sc-stat-icon">✍️</div>
          <div class="sc-stat-label">Write Test</div>
          <div class="sc-stat-value" id="sc-write-val">${spinner}</div>
          <div class="sc-stat-sub">Read/write access</div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="sc-tabs">
        <div class="sc-tab active" onclick="scSwitchTab('overview',this)">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          Overview
        </div>
        <div class="sc-tab" onclick="scSwitchTab('logs',this)">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
          Error Logs
          <span class="sc-tab-badge" id="sc-log-badge">0</span>
        </div>
        <div class="sc-tab" onclick="scSwitchTab('rules',this)">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Security Rules
        </div>
      </div>

      <!-- Tab Body -->
      <div class="sc-body">

        <!-- Overview Tab -->
        <div class="sc-tab-panel active" id="sc-panel-overview">

          <div class="sc-info-card">
            <div class="sc-info-card-title">
              <svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
              Firebase Project
            </div>
            <div class="sc-info-row">
              <span class="sc-info-key">Project ID</span>
              <span class="sc-info-val" style="color:var(--cyan);">${escHtml(FIREBASE_CFG.projectId || '—')}</span>
            </div>
            <div class="sc-info-row">
              <span class="sc-info-key">Database URL</span>
              <span class="sc-info-val" style="font-size:10px;">${escHtml(FIREBASE_CFG.databaseURL || '—')}</span>
            </div>
            <div class="sc-info-row">
              <span class="sc-info-key">Admin Email</span>
              <span class="sc-info-val" style="color:var(--green);">${escHtml(ADMIN_EMAIL)}</span>
            </div>
          </div>

          <div class="sc-info-card">
            <div class="sc-info-card-title">
              <svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              Live Status
            </div>
            <div class="sc-info-row">
              <span class="sc-info-key">RTDB Connection</span>
              <span class="sc-info-val" id="sc-conn-pill">${spinner}</span>
            </div>
            <div class="sc-info-row">
              <span class="sc-info-key">Accounts Path</span>
              <span class="sc-info-val" id="sc-acc-pill">${spinner}</span>
            </div>
            <div class="sc-info-row">
              <span class="sc-info-key">Settings Path</span>
              <span class="sc-info-val" id="sc-sett-pill">${spinner}</span>
            </div>
            <div class="sc-info-row">
              <span class="sc-info-key">Write Access</span>
              <span class="sc-info-val" id="sc-write-pill">${spinner}</span>
            </div>
          </div>

        </div>

        <!-- Logs Tab -->
        <div class="sc-tab-panel" id="sc-panel-logs">
          <div class="sc-log-wrap">
            <div class="sc-log-header">
              <div style="display:flex;align-items:center;gap:8px;">
                <span>🛡️ Error Log</span>
                <span id="sc-log-count-pill" style="display:none;background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);color:#ef4444;font-size:10px;padding:1px 8px;border-radius:20px;font-weight:700;"></span>
              </div>
              <div style="display:flex;gap:6px;">
                <button class="sc-log-clear" onclick="window._scClearLogs && window._scClearLogs()">🗑️ Clear</button>
                <button class="sc-log-clear" style="background:rgba(59,130,246,0.1);border-color:rgba(59,130,246,0.2);color:#60a5fa;" onclick="window._scRefreshLogs && window._scRefreshLogs()">🔄 Refresh</button>
              </div>
            </div>
            <div class="sc-log-lines" id="sc-log-lines">
              <div class="sc-no-log">⏳ Loading logs…</div>
            </div>
          </div>
        </div>

        <!-- Rules Tab -->
        <div class="sc-tab-panel" id="sc-panel-rules">
          <div class="sc-rules-alert">
            <span style="font-size:16px;flex-shrink:0;">⚠️</span>
            <div>
              সব paths Firebase Rules এ থাকা আবশ্যক — না থাকলে silent failures হয়।
              নিচের rules copy করে <strong>Firebase Console → Realtime Database → Rules</strong> tab এ paste করুন।
              <br style="margin-bottom:6px;">
              <code style="background:rgba(239,68,68,0.18);padding:1px 5px;border-radius:4px;font-family:var(--mono);font-size:10px;">accounts</code>
              <code style="background:rgba(239,68,68,0.18);padding:1px 5px;border-radius:4px;font-family:var(--mono);font-size:10px;">vault_logs</code>
              <code style="background:rgba(239,68,68,0.18);padding:1px 5px;border-radius:4px;font-family:var(--mono);font-size:10px;">admin_settings</code>
              <code style="background:rgba(239,68,68,0.18);padding:1px 5px;border-radius:4px;font-family:var(--mono);font-size:10px;">api_keys</code>
              <code style="background:rgba(34,197,94,0.18);padding:1px 5px;border-radius:4px;font-family:var(--mono);font-size:10px;color:#22c55e;">loginLogs</code>
              <br style="margin-bottom:4px;">
              <span style="font-size:10px;color:var(--text-muted);">
                ⚡ <strong>loginLogs</strong> path না থাকলে cross-device login history কাজ করবে না।
                Root level এ <code style="font-size:9px;">.read: false</code> এবং <code style="font-size:9px;">.write: false</code> রাখুন।
              </span>
            </div>
          </div>
          <div class="sc-rules-code-wrap">
            <div class="sc-rules-code-header">
              <span>📋 firebase-rules.json</span>
              <button class="sc-copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('sc-rules-pre').textContent).then(()=>showToast('Rules copied! Go to Firebase Console → Realtime Database → Rules','success'))">
                <svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                Copy Rules
              </button>
            </div>
            <pre class="sc-rules-pre" id="sc-rules-pre">${escHtml(rulesJson)}</pre>
          </div>
        </div>

      </div>
    </div>
  `;

  document.body.appendChild(overlay);
  overlay.addEventListener("click", e => { if (e.target === overlay) overlay.remove(); });

  // ─── Tab switcher ───
  window.scSwitchTab = function(name, el) {
    document.querySelectorAll(".sc-tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".sc-tab-panel").forEach(p => p.classList.remove("active"));
    el.classList.add("active");
    const panel = document.getElementById("sc-panel-" + name);
    if (panel) panel.classList.add("active");
  };

  const pill = (color, dot, text) =>
    `<span class="sc-pill ${color}"><span class="sc-pill-dot${dot ? ' pulse' : ''}"></span>${escHtml(text)}</span>`;

  // ─── Connection check ───
  const connRef = ref(db, ".info/connected");
  onValue(connRef, (snap) => {
    const ok = snap.val() === true;
    const pv = document.getElementById("sc-conn-pill");
    const cv = document.getElementById("sc-conn-val");
    if (pv) pv.innerHTML = ok ? pill("green", true, "Connected") : pill("red", false, "Offline");
    if (cv) cv.textContent = ok ? "● ON" : "● OFF";
    if (cv) cv.style.color = ok ? "var(--green)" : "var(--red)";
  }, { onlyOnce: true });

  // ─── Accounts count ───
  try {
    const snap = await new Promise((res, rej) =>
      onValue(ref(db, ADMIN_COLLECTION), res, rej, { onlyOnce: true }));
    const count = snap.val() ? Object.keys(snap.val()).length : 0;
    const pv = document.getElementById("sc-acc-pill");
    const cv = document.getElementById("sc-acc-val");
    if (pv) pv.innerHTML = pill("green", false, `${count} accounts ✓`);
    if (cv) { cv.textContent = count; cv.style.color = "var(--green)"; }
  } catch(e) {
    const pv = document.getElementById("sc-acc-pill");
    const cv = document.getElementById("sc-acc-val");
    if (pv) pv.innerHTML = pill("red", false, "Access denied");
    if (cv) { cv.textContent = "ERR"; cv.style.color = "var(--red)"; }
  }


  // ─── Settings check ───
  try {
    const snap = await new Promise((res, rej) =>
      onValue(ref(db, ADMIN_SETTINGS_PATH), res, rej, { onlyOnce: true }));
    const keys = snap.val() ? Object.keys(snap.val()).length : 0;
    const pv = document.getElementById("sc-sett-pill");
    if (pv) pv.innerHTML = pill("cyan", false, `${keys} settings ✓`);
  } catch(e) {
    const pv = document.getElementById("sc-sett-pill");
    if (pv) pv.innerHTML = pill("red", false, "Access denied");
  }

  // ─── Write test ───
  try {
    const testRef = ref(db, `${ADMIN_SETTINGS_PATH}/__write_test__`);
    await set(testRef, Date.now());
    await remove(testRef);
    const pv = document.getElementById("sc-write-pill");
    const cv = document.getElementById("sc-write-val");
    if (pv) pv.innerHTML = pill("green", false, "Write OK ✓");
    if (cv) { cv.textContent = "OK"; cv.style.color = "var(--green)"; }
  } catch(e) {
    const pv = document.getElementById("sc-write-pill");
    const cv = document.getElementById("sc-write-val");
    if (pv) pv.innerHTML = pill("red", false, "Denied");
    if (cv) { cv.textContent = "FAIL"; cv.style.color = "var(--red)"; }
  }

  // ─── Error Logs: render helper ───
  function _scRenderLogs() {
    const logLines = document.getElementById("sc-log-lines");
    const logBadge = document.getElementById("sc-log-badge");
    const countPill = document.getElementById("sc-log-count-pill");
    if (!logLines) return;
    const errors = VaultDebug._getErrors ? VaultDebug._getErrors() : [];
    const errOnly  = errors.filter(e => e.level === "error");
    const warnOnly = errors.filter(e => e.level === "warn");

    if (logBadge) {
      logBadge.textContent = errors.length || "0";
      if (errors.length > 0) logBadge.classList.add("show"); else logBadge.classList.remove("show");
    }
    if (countPill) {
      if (errors.length > 0) {
        countPill.style.display = "inline-block";
        countPill.textContent = `${errors.length} issue${errors.length !== 1 ? "s" : ""}`;
      } else {
        countPill.style.display = "none";
      }
    }

    if (errors.length === 0) {
      logLines.innerHTML = `
        <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:40px 20px;gap:10px;">
          <div style="width:48px;height:48px;border-radius:50%;background:rgba(34,197,94,0.12);border:1px solid rgba(34,197,94,0.2);display:flex;align-items:center;justify-content:center;font-size:22px;">✅</div>
          <div style="font-size:13px;font-weight:600;color:var(--green,#22c55e);">System Clean</div>
          <div style="font-size:11px;color:var(--text3,#64748b);text-align:center;">No errors or warnings detected.<br>All systems are running normally.</div>
        </div>`;
      return;
    }

    const levelMeta = {
      error: { icon: "🔴", label: "ERROR", bg: "rgba(239,68,68,0.08)", border: "rgba(239,68,68,0.18)", color: "#ef4444", dot: "#ef4444" },
      warn:  { icon: "🟡", label: "WARN",  bg: "rgba(245,158,11,0.08)", border: "rgba(245,158,11,0.18)", color: "#f59e0b", dot: "#f59e0b" }
    };

    // Summary bar (negative margin to overcome parent padding and go full-width)
    const summaryHtml = `
      <div style="display:flex;gap:8px;padding:10px 14px;border-bottom:1px solid rgba(255,255,255,0.05);margin:-8px -12px 4px -12px;background:rgba(0,0,0,0.2);">
        <div style="flex:1;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.15);border-radius:8px;padding:8px 12px;text-align:center;">
          <div style="font-size:18px;font-weight:700;color:#ef4444;">${errOnly.length}</div>
          <div style="font-size:10px;color:var(--text3,#64748b);margin-top:2px;">Errors</div>
        </div>
        <div style="flex:1;background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.15);border-radius:8px;padding:8px 12px;text-align:center;">
          <div style="font-size:18px;font-weight:700;color:#f59e0b;">${warnOnly.length}</div>
          <div style="font-size:10px;color:var(--text3,#64748b);margin-top:2px;">Warnings</div>
        </div>
        <div style="flex:1;background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.15);border-radius:8px;padding:8px 12px;text-align:center;">
          <div style="font-size:18px;font-weight:700;color:#60a5fa;">${errors.length}</div>
          <div style="font-size:10px;color:var(--text3,#64748b);margin-top:2px;">Total</div>
        </div>
      </div>`;

    const logsHtml = errors.slice().reverse().map((e, i) => {
      const m = levelMeta[e.level] || levelMeta.warn;
      return `
        <div style="display:flex;gap:10px;padding:10px 14px;border-bottom:1px solid rgba(255,255,255,0.04);background:${i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)"};">
          <div style="width:28px;height:28px;border-radius:7px;background:${m.bg};border:1px solid ${m.border};display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0;">${m.icon}</div>
          <div style="flex:1;min-width:0;">
            <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;">
              <span style="font-size:9px;font-weight:700;padding:1px 6px;border-radius:10px;background:${m.bg};border:1px solid ${m.border};color:${m.color};">${m.label}</span>
              <span style="font-size:10px;color:var(--text3,#64748b);">${escHtml(e.time)}</span>
            </div>
            <div style="font-size:11px;color:var(--text2,#94a3b8);font-family:var(--mono,'monospace');word-break:break-all;line-height:1.5;">${escHtml(e.msg)}</div>
          </div>
        </div>`;
    }).join("");

    logLines.innerHTML = summaryHtml + `<div style="overflow-y:auto;max-height:260px;">${logsHtml}</div>`;
  }

  window._scClearLogs = function() {
    const logLines = document.getElementById("sc-log-lines");
    if (logLines) logLines.innerHTML = `
      <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:40px 20px;gap:10px;">
        <div style="font-size:22px;">🗑️</div>
        <div style="font-size:12px;color:var(--text3,#64748b);">Logs cleared from view</div>
      </div>`;
    const badge = document.getElementById("sc-log-badge");
    const pill = document.getElementById("sc-log-count-pill");
    if (badge) { badge.textContent = "0"; badge.classList.remove("show"); }
    if (pill) pill.style.display = "none";
  };

  window._scRefreshLogs = function() {
    _scRenderLogs();
  };

  _scRenderLogs();
};

// ══════════════════════════════════════════════════════
// SEARCH CLEAR BUTTON  ·  Credit: RAIHAN
// ══════════════════════════════════════════════════════

window.clearSearch = function() {
  const input = document.getElementById("search-input");
  if (input) { input.value = ""; filterAccounts(); input.focus(); }
  const clrBtn = document.getElementById("search-clear-btn");
  if (clrBtn) clrBtn.style.display = "none";
};

window.saveImgbbKey = async function(e) {
  e.preventDefault();
  const key = document.getElementById("imgbb-api-key").value.trim();
  const alertEl = document.getElementById("imgbb-alert");
  if (!key) {
    alertEl.className = "alert alert-error";
    alertEl.textContent = "API key cannot be empty.";
    alertEl.classList.remove("hidden");
    return;
  }
  try {
    await saveSetting("imgbb_key", key);
    showToast("ImgBB API key saved to Firebase.", "success");
    showApiKeyState("imgbb", key);
  } catch (err) {
    alertEl.className = "alert alert-error";
    alertEl.textContent = "Save failed: " + err.message;
    alertEl.classList.remove("hidden");
  }
};

// ═════════════════════════════════════════════════════════════════
// SETTINGS — LOGIN 2FA SETUP / TOGGLE / KEY DISPLAY
// ═════════════════════════════════════════════════════════════════
let _login2faPendingSecret = ""; // generated during setup, saved on verify
let _login2faKeyShown = false;

function _genBase32Secret(length = 32) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  let out = "";
  for (let i = 0; i < length; i++) out += chars[arr[i] % 32];
  return out;
}

function _formatKey(k) {
  return (k || "").replace(/(.{4})/g, "$1 ").trim();
}

window.renderLogin2FAPanel = function() {
  const enabled = window._settings.login_2fa_enabled === "1";
  const secret  = window._settings.login_2fa_secret || "";
  const toggle  = document.getElementById("login-2fa-toggle");
  const okBox   = document.getElementById("login-2fa-enabled-box");
  const setupBox= document.getElementById("login-2fa-setup-panel");
  if (toggle) toggle.checked = enabled;
  if (okBox)  okBox.style.display = (enabled && secret) ? "block" : "none";
  if (setupBox) setupBox.style.display = "none";
  // Reset key display
  _login2faKeyShown = false;
  const disp = document.getElementById("login2fa-key-display");
  if (disp && secret) disp.textContent = "••••-••••-••••-••••";
};

window.onLogin2FAToggle = async function(e) {
  const checked = e.target.checked;
  if (checked) {
    // Start setup wizard — generate secret, show key + QR
    _login2faPendingSecret = _genBase32Secret(32);
    const keyEl = document.getElementById("login2fa-setup-key");
    if (keyEl) keyEl.textContent = _formatKey(_login2faPendingSecret);
    // Build otpauth URL for QR
    const issuer = encodeURIComponent("Private Vault");
    const account = encodeURIComponent("admin@vault.local");
    const otpauth = `otpauth://totp/${issuer}:${account}?secret=${_login2faPendingSecret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    const qrBox = document.getElementById("login2fa-qr-box");
    if (qrBox) {
      // Use external QR generator (image-only, no JS lib needed)
      qrBox.innerHTML = `<img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(otpauth)}" alt="QR Code" width="180" height="180" style="border-radius:8px;background:#fff;padding:6px;" />`;
    }
    const setupBox = document.getElementById("login-2fa-setup-panel");
    const okBox    = document.getElementById("login-2fa-enabled-box");
    if (setupBox) setupBox.style.display = "block";
    if (okBox)    okBox.style.display = "none";
    setTimeout(() => {
      const inp = document.getElementById("login2fa-verify-code");
      if (inp) inp.focus();
    }, 200);
  } else {
    // Disabling — confirm
    const ok = confirm("Disable Login 2FA? Anyone with the password will be able to log in.");
    if (!ok) { e.target.checked = true; return; }
    await saveSetting("login_2fa_enabled", "0");
    await saveSetting("login_2fa_secret", "");
    showToast("Login 2FA disabled.", "info");
    if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("warn", "security", "Login 2FA disabled");
    renderLogin2FAPanel();
  }
};

window.cancelLogin2FASetup = function() {
  _login2faPendingSecret = "";
  const setupBox = document.getElementById("login-2fa-setup-panel");
  if (setupBox) setupBox.style.display = "none";
  const tog = document.getElementById("login-2fa-toggle");
  if (tog) tog.checked = (window._settings.login_2fa_enabled === "1");
  const errEl = document.getElementById("login2fa-verify-error");
  if (errEl) errEl.classList.add("hidden");
};

window.copyLogin2FASetupKey = function() {
  if (!_login2faPendingSecret) return;
  navigator.clipboard.writeText(_login2faPendingSecret).then(
    () => showToast("Secret key copied.", "success"),
    () => showToast("Copy failed.", "error")
  );
};

window.verifyLogin2FASetup = async function(e) {
  e.preventDefault();
  const inp = document.getElementById("login2fa-verify-code");
  const errEl = document.getElementById("login2fa-verify-error");
  const code = (inp.value || "").replace(/\D/g, "");
  if (code.length !== 6) {
    errEl.textContent = "Enter the 6-digit code from your authenticator.";
    errEl.classList.remove("hidden");
    return;
  }
  if (!_login2faPendingSecret) {
    errEl.textContent = "Setup expired — toggle off and on again.";
    errEl.classList.remove("hidden");
    return;
  }
  const expected = await generateTOTP(_login2faPendingSecret);
  let valid = (code === expected);
  if (!valid) {
    const counter = Math.floor(Date.now() / 1000 / 30);
    for (const off of [-1, 1]) {
      const c = await generateTOTPAt(_login2faPendingSecret, counter + off);
      if (c === code) { valid = true; break; }
    }
  }
  if (!valid) {
    errEl.textContent = "Invalid code. Try the latest 6 digits in your app.";
    errEl.classList.remove("hidden");
    return;
  }
  // Save & enable
  await saveSetting("login_2fa_secret", _login2faPendingSecret);
  await saveSetting("login_2fa_enabled", "1");
  _login2faPendingSecret = "";
  errEl.classList.add("hidden");
  inp.value = "";
  showToast("Login 2FA enabled. Next login will require your code.", "success");
  if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("ok", "security", "Login 2FA enabled");
  renderLogin2FAPanel();
};

window.toggleLogin2FAKey = function() {
  const disp = document.getElementById("login2fa-key-display");
  const secret = window._settings.login_2fa_secret || "";
  if (!disp || !secret) return;
  _login2faKeyShown = !_login2faKeyShown;
  disp.textContent = _login2faKeyShown ? _formatKey(secret) : "••••-••••-••••-••••";
};

window.copyLogin2FAKey = function() {
  const secret = window._settings.login_2fa_secret || "";
  if (!secret) return showToast("No 2FA key to copy.", "error");
  navigator.clipboard.writeText(secret).then(
    () => showToast("2FA secret copied.", "success"),
    () => showToast("Copy failed.", "error")
  );
};

// ═════════════════════════════════════════════════════════════════
// SETTINGS — LOGIN HISTORY (last 10)
// ═════════════════════════════════════════════════════════════════
function _statusBadge(status) {
  const map = {
    "success":      { cls: "ok",    txt: "SUCCESS" },
    "fail":         { cls: "err",   txt: "FAILED" },
    "blocked":      { cls: "err",   txt: "IP BLOCKED" },
    "rate-limited": { cls: "warn",  txt: "RATE-LIMITED" },
    "2fa-fail":     { cls: "warn",  txt: "2FA FAIL" }
  };
  const m = map[status] || { cls: "warn", txt: (status || "UNKNOWN").toUpperCase() };
  return `<span class="login-log-status ${m.cls}">${m.txt}</span>`;
}

function _fmtTime(ts) {
  if (!ts) return "--";
  const d = new Date(ts);
  const now = Date.now();
  const diff = now - ts;
  if (diff < 60000) return Math.floor(diff/1000) + "s ago";
  if (diff < 3600000) return Math.floor(diff/60000) + "m ago";
  if (diff < 86400000) return Math.floor(diff/3600000) + "h ago";
  return d.toLocaleString();
}

window.renderLoginLogList = async function(rtdbSnap) {
  const wrap = document.getElementById("login-logs-list");
  if (!wrap) return;
  wrap.innerHTML = `<div class="login-logs-empty">Loading…</div>`;

  let logs;
  if (rtdbSnap && typeof rtdbSnap.val === "function") {
    // Called from onValue — use snapshot directly, no second get() call (avoids infinite loop)
    const remote = rtdbSnap.val() || {};
    const remoteEntries = Object.keys(remote).map(k => ({ _key: k, ...remote[k] }));
    // Merge with local logs (dedupe by ts+status+ip)
    const local = LoginSecurity.getLocalLogs ? LoginSecurity.getLocalLogs() : [];
    const byKey = new Map();
    remoteEntries.forEach(e => byKey.set(`${e.ts}_${e.status}_${e.ip}`, e));
    local.forEach(e => {
      const k = `${e.ts}_${e.status}_${e.ip}`;
      if (!byKey.has(k)) byKey.set(k, e);
    });
    logs = [...byKey.values()].sort((a, b) => (b.ts || 0) - (a.ts || 0)).slice(0, 50);
  } else {
    // Called manually (refresh button, etc.) — safe to use getLogs
    logs = await LoginSecurity.getLogs(50);
  }
  if (!logs || !logs.length) {
    wrap.innerHTML = `<div class="login-logs-empty">No login attempts recorded yet.</div>`;
    return;
  }
  const blocked    = LoginSecurity.getBlockedIPsCached().map(x => x.ip);
  const myDeviceId = LoginSecurity.getDeviceId();
  wrap.innerHTML = logs.map(l => {
    const isBlocked    = blocked.includes(l.ip);
    const isThisDevice = l.deviceId && l.deviceId === myDeviceId;
    const loc = [l.city, l.region, l.country].filter(x => x && x !== "?").join(", ") || "Unknown location";

    // Build device detail chips
    const browserStr  = [l.browser, l.browserVersion].filter(Boolean).join(" ");
    const osStr       = [l.os, l.osVersion].filter(Boolean).join(" ");
    const chips = [
      l.deviceType ? `<span class="llg-chip device">${escHtml(l.deviceType)}</span>` : "",
      browserStr   ? `<span class="llg-chip browser">🌐 ${escHtml(browserStr)}</span>` : "",
      osStr        ? `<span class="llg-chip os">💻 ${escHtml(osStr)}</span>` : "",
      l.screen     ? `<span class="llg-chip">🖥 ${escHtml(l.screen)}</span>` : "",
      l.tz         ? `<span class="llg-chip">🕐 ${escHtml(l.tz)}</span>` : "",
      l.lang       ? `<span class="llg-chip">🌍 ${escHtml(l.lang)}</span>` : "",
      l.memory     ? `<span class="llg-chip">🧠 ${escHtml(l.memory)}</span>` : "",
      l.cores      ? `<span class="llg-chip">⚙ ${escHtml(l.cores)}</span>` : "",
      l.isp        ? `<span class="llg-chip">📡 ${escHtml(l.isp)}</span>` : "",
    ].filter(Boolean).join("");

    return `
      <div class="login-log-row" data-key="${escHtml(l._key || "")}">
        <div class="login-log-main">
          <div class="login-log-top">
            ${_statusBadge(l.status)}
            <span class="login-log-time" title="${escHtml(new Date(l.ts).toLocaleString())}">${_fmtTime(l.ts)}</span>
            ${isThisDevice ? `<span class="login-log-this-device">This device</span>` : ""}
          </div>
          <div class="login-log-ip mono">
            <svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>
            <strong>${escHtml(l.ip || "unknown")}</strong>
            <span class="login-log-loc">· ${escHtml(loc)}</span>
          </div>
          ${chips ? `<div class="llg-chips">${chips}</div>` : ""}
          ${l.reason ? `<div class="login-log-reason-row">⚠ ${escHtml(l.reason)}</div>` : ""}
        </div>
        <div class="login-log-actions">
          ${l.ip && l.ip !== "unknown" ? (isBlocked
            ? `<button class="api-action-btn" disabled title="Already blocked"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> Blocked</button>`
            : `<button class="api-action-btn api-action-delete" onclick="blockIPFromLog('${escHtml(l.ip)}')" title="Block this IP"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> Block</button>`)
            : ""}
          <button class="api-action-btn" onclick="deleteLoginLog('${escHtml(l._key || "")}', ${l.ts})" title="Delete"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg></button>
        </div>
      </div>`;
  }).join("");
};

window.refreshLoginLogs = async function() {
  LoginSecurity.refreshIPCache();
  await LoginSecurity.syncBlockedIPsFromRTDB();
  await renderLoginLogList();
  await renderBlockedIPsList();
  showToast("Login history refreshed.", "info", 1800);
};

window.deleteLoginLog = async function(key, ts) {
  // Delete from RTDB if key exists
  if (key) {
    try { await remove(ref(db, `loginLogs/${key}`)); } catch (e) { console.warn(e.message); }
  }
  // Delete from local cache by ts match
  try {
    const list = JSON.parse(localStorage.getItem("pv_login_logs_local") || "[]");
    const next = list.filter(x => x.ts !== ts);
    localStorage.setItem("pv_login_logs_local", JSON.stringify(next));
  } catch {}
  showToast("Log entry deleted.", "info", 1500);
  renderLoginLogList();
};

window.clearAllLoginLogs = async function() {
  if (!confirm("Delete ALL login history? This cannot be undone.")) return;
  await LoginSecurity.clearAllLogs();
  showToast("All login logs cleared.", "success");
  if (typeof RealtimeLogger !== "undefined") RealtimeLogger.push("warn", "security", "All login logs cleared");
  renderLoginLogList();
};

window.blockIPFromLog = async function(ip) {
  if (!ip || ip === "unknown") return;
  if (!confirm(`Block IP ${ip}? This IP will not be able to log in from any device.`)) return;
  await LoginSecurity.blockIP(ip, "Blocked from login history");
  showToast(`IP ${ip} blocked.`, "success");
  renderLoginLogList();
  renderBlockedIPsList();
};

// ═════════════════════════════════════════════════════════════════
// SETTINGS — BLOCKED IPs MANAGER
// ═════════════════════════════════════════════════════════════════
window.renderBlockedIPsList = async function() {
  const wrap = document.getElementById("blocked-ips-list");
  const badge = document.getElementById("blocked-ips-count");
  if (!wrap) return;
  // Always pull latest from RTDB so it stays in sync between sessions
  await LoginSecurity.syncBlockedIPsFromRTDB();
  const list = LoginSecurity.getBlockedIPsCached();
  if (badge) badge.textContent = String(list.length);
  if (!list.length) {
    wrap.innerHTML = `<div class="blocked-ips-empty">No blocked IPs.</div>`;
    return;
  }
  list.sort((a,b) => (b.blockedAt || 0) - (a.blockedAt || 0));
  wrap.innerHTML = list.map(x => `
    <div class="blocked-ip-row">
      <div class="blocked-ip-main">
        <div class="blocked-ip-addr mono">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
          ${escHtml(x.ip)}
        </div>
        <div class="blocked-ip-meta">
          <span>${escHtml(x.reason || "manual")}</span>
          <span>· ${_fmtTime(x.blockedAt)}</span>
        </div>
      </div>
      <button class="api-action-btn api-action-edit" onclick="unblockIPManual('${escHtml(x.ip)}')" title="Unblock">
        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
        Unblock
      </button>
    </div>
  `).join("");
};

window.addBlockedIPManual = async function() {
  const inp = document.getElementById("blocked-ip-input");
  const ip = (inp.value || "").trim();
  if (!ip) return showToast("Enter an IP address first.", "error");
  // Loose IPv4 / IPv6 validation
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[0-9a-fA-F:]+$/;
  if (!ipv4.test(ip) && !(ipv6.test(ip) && ip.includes(":"))) {
    return showToast("Invalid IP address format.", "error");
  }
  await LoginSecurity.blockIP(ip, "Manual block");
  inp.value = "";
  showToast(`IP ${ip} blocked.`, "success");
  renderBlockedIPsList();
  renderLoginLogList();
};

window.unblockIPManual = async function(ip) {
  if (!confirm(`Unblock IP ${ip}?`)) return;
  await LoginSecurity.unblockIP(ip);
  showToast(`IP ${ip} unblocked.`, "info");
  renderBlockedIPsList();
  renderLoginLogList();
};

// ══════════════════════════════════════════════════════
// AI SUPPORT  ·  Credit: RAIHAN
// ══════════════════════════════════════════════════════

window._aiMode = "chat";
window._aiMessages = [];

window.toggleAI = async function(checked) {
  await saveSetting("ai_enabled", checked ? "1" : "0");
  const panel = document.getElementById("ai-settings-panel");
  if (panel) panel.style.display = checked ? "block" : "none";
};

window.switchAIProvider = async function(provider) {
  await saveSetting("ai_provider", provider);
  ["openai", "gemini"].forEach(p => {
    const tab = document.getElementById("ai-tab-" + p);
    const fields = document.getElementById("ai-fields-" + p);
    if (tab) tab.classList.toggle("active", p === provider);
    if (fields) fields.classList.toggle("active", p === provider);
  });
};

window.saveAIKey = async function() {
  const keyEl = document.getElementById("openai-api-key");
  const alertEl = document.getElementById("ai-key-alert");
  const key = keyEl ? keyEl.value.trim() : "";
  if (!key) {
    if (alertEl) {
      alertEl.className = "alert alert-error";
      alertEl.textContent = "API key cannot be empty.";
      alertEl.classList.remove("hidden");
    }
    return;
  }
  try {
    await saveSetting("openai_key", key);
    showToast("OpenAI API key saved to Firebase.", "success");
    showApiKeyState("openai", key);
  } catch (err) { showToast("Save failed: " + err.message, "error"); }
};

window.saveGeminiKey = async function() {
  const keyEl = document.getElementById("gemini-api-key");
  const alertEl = document.getElementById("ai-key-alert");
  const key = keyEl ? keyEl.value.trim() : "";
  if (!key) {
    if (alertEl) {
      alertEl.className = "alert alert-error";
      alertEl.textContent = "Gemini API key cannot be empty.";
      alertEl.classList.remove("hidden");
    }
    return;
  }
  try {
    await saveSetting("gemini_key", key);
    showToast("Gemini API key saved to Firebase.", "success");
    showApiKeyState("gemini", key);
  } catch (err) { showToast("Save failed: " + err.message, "error"); }
};

window.setAIMode = function(mode) {
  window._aiMode = mode;
  ["chat", "parse", "analyze"].forEach(m => {
    const btn = document.getElementById("ai-mode-" + m);
    if (btn) btn.classList.toggle("active", m === mode);
  });
  const input = document.getElementById("ai-chat-input");
  if (input) {
    const placeholders = {
      chat: "Ask anything about account security…",
      parse: "Paste account info: e.g. 'Instagram: email test@gmail.com, pass Abc@123'",
      analyze: "Describe or paste an account to analyze its security…"
    };
    input.placeholder = placeholders[mode] || input.placeholder;
  }
};

window.aiChatKeydown = function(e) {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendAIChat();
  }
};

window.aiQuickCmd = function(text) {
  const input = document.getElementById("ai-chat-input");
  if (input) {
    input.value = text;
    input.focus();
    sendAIChat();
  }
};

function appendAIMessage(role, text) {
  const container = document.getElementById("ai-chat-messages");
  if (!container) return;
  const div = document.createElement("div");
  div.className = "ai-msg " + (role === "user" ? "ai-msg-user" : "ai-msg-bot");
  div.innerHTML = role === "user"
    ? `<div class="ai-msg-bubble">${escHtml(text)}</div>`
    : `<div class="ai-msg-avatar">AI</div><div class="ai-msg-bubble">${escHtml(text)}</div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div;
}

async function callOpenAI(messages, mode) {
  const res = await fetch("/api/ai", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ provider: "openai", messages, mode, key: window._settings.openai_key || "" })
  });
  const json = await res.json();
  if (!json.ok) throw new Error(json.error || "OpenAI error");
  return json.text || "";
}

async function callGemini(messages, mode) {
  const res = await fetch("/api/ai", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ provider: "gemini", messages, mode, key: window._settings.gemini_key || "" })
  });
  const json = await res.json();
  if (!json.ok) throw new Error(json.error || "Gemini error");
  return json.text || "";
}

window.sendAIChat = async function() {
  const input = document.getElementById("ai-chat-input");
  const sendBtn = document.getElementById("ai-send-btn");
  const text = input ? input.value.trim() : "";
  if (!text) return;

  input.value = "";
  input.disabled = true;
  if (sendBtn) sendBtn.disabled = true;

  appendAIMessage("user", text);
  window._aiMessages.push({ role: "user", content: text });

  const thinkingDiv = document.createElement("div");
  thinkingDiv.className = "ai-msg ai-msg-bot";
  thinkingDiv.innerHTML = `<div class="ai-msg-avatar">AI</div><div class="ai-msg-bubble" style="opacity:0.6;">Thinking…</div>`;
  const container = document.getElementById("ai-chat-messages");
  if (container) { container.appendChild(thinkingDiv); container.scrollTop = container.scrollHeight; }

  const mode = window._aiMode;
  const provider = window._settings.ai_provider || "openai";

  // AI Direct Actions — process commands locally first
  const directReply = await processAIDirectAction(text);
  if (directReply !== null) {
    if (thinkingDiv.parentNode) thinkingDiv.parentNode.removeChild(thinkingDiv);
    const botDiv = appendAIMessage("bot", directReply);
    window._aiMessages.push({ role: "assistant", content: directReply });
    if (input) input.disabled = false;
    if (sendBtn) sendBtn.disabled = false;
    return;
  }

  try {
    let reply;
    if (provider === "gemini") {
      reply = await callGemini(window._aiMessages, mode);
    } else {
      reply = await callOpenAI(window._aiMessages, mode);
    }

    if (thinkingDiv.parentNode) thinkingDiv.parentNode.removeChild(thinkingDiv);

    window._aiMessages.push({ role: "assistant", content: reply });

    if (mode === "parse") {
      try {
        const cleanReply = reply.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
        const parsed = JSON.parse(cleanReply);
        if (parsed.error) {
          appendAIMessage("bot", parsed.error);
        } else {
          appendAIMessage("bot", "I found this account info. Review and confirm to save it:");
          showParsedCard(parsed);
        }
      } catch {
        appendAIMessage("bot", reply);
      }
    } else {
      appendAIMessage("bot", reply);
    }
  } catch (err) {
    if (thinkingDiv.parentNode) thinkingDiv.parentNode.removeChild(thinkingDiv);
    appendAIMessage("bot", "Error: " + err.message);
  }

  input.disabled = false;
  if (sendBtn) sendBtn.disabled = false;
  input.focus();
};

window._lastParsedData = null;

function showParsedCard(data) {
  window._lastParsedData = data;
  const card = document.getElementById("ai-parsed-card");
  if (!card) return;
  const fields = ["platform","name","uid","email","number","password","dob","note","status","recoveryKey"];
  const labels = { platform:"Platform", name:"Name", uid:"Username/UID", email:"Email", number:"Phone", password:"Password", dob:"Date of Birth", note:"Note", status:"Status", recoveryKey:"Recovery Key" };
  let rows = "";
  fields.forEach(f => {
    if (data[f]) rows += `<div class="info-row"><span class="info-label">${labels[f]}</span><span class="info-value mono">${escHtml(data[f])}</span></div>`;
  });
  card.innerHTML = `
    <div class="ai-parsed-card-inner">
      <div class="ai-parsed-card-title">Parsed Account</div>
      ${rows}
      <div style="display:flex;gap:8px;margin-top:10px;">
        <button class="btn btn-primary btn-sm" onclick="confirmParsedSave()" data-testid="button-confirm-parse">Save Account</button>
        <button class="btn btn-sm" onclick="document.getElementById('ai-parsed-card').style.display='none'" style="background:var(--surface2);color:var(--text2);">Dismiss</button>
      </div>
    </div>`;
  card.style.display = "block";
}

window.confirmParsedSave = async function() {
  const data = window._lastParsedData;
  if (!data) return;
  const card = document.getElementById("ai-parsed-card");
  const now = Date.now();
  try {
    await push(ref(db, ADMIN_COLLECTION), { ...data, createdAt: now, updatedAt: now });
    addVaultLog("added", data.name || data.email, data.platform, "Added via AI Assistant");
    if (card) card.style.display = "none";
    showToast("Account saved from AI parse!", "success");
    appendAIMessage("bot", "Account saved successfully!");
  } catch (err) {
    showToast("Save failed: " + err.message, "error");
  }
};


// ══════════════════════════════════════════════════════
// POWER MODALS — Analytics, Bulk Parser
// Credit: RAIHAN
// ══════════════════════════════════════════════════════
window.closePowerModal = function(id) {
  document.getElementById(id)?.classList.remove("open");
};
window.closePowerModalOnOverlay = function(e, id) {
  if (e.target.id === id) window.closePowerModal(id);
};

// ── AI ASSISTANT MODAL ──
function _renderIntroChips() {
  const wrap = document.getElementById("ai-intro-chips");
  if (!wrap || typeof AI_CMD_DEFS === "undefined") return;
  wrap.innerHTML = "";
  AI_CMD_DEFS.forEach(d => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ai-chip" + (d.style === "danger" ? " danger" : "");
    btn.innerHTML =
      `<span class="ai-chip-ico">${d.icon || "•"}</span><span>${d.label}</span>`;
    // Search chip is a prefix → prefill the input instead of sending
    const isPrefill = /\s$/.test(d.cmd);
    btn.addEventListener("click", () => {
      const input = document.getElementById("ai-modal-input");
      if (isPrefill && input) {
        input.value = d.cmd;
        input.focus();
        try { input.setSelectionRange(input.value.length, input.value.length); } catch(_){}
      } else {
        window.aiSendCmd(d.cmd);
      }
    });
    wrap.appendChild(btn);
  });
}

window.openAIModal = function() {
  if (isMobile()) closeSidebar();
  const modal = document.getElementById("ai-modal");
  if (!modal) return;
  modal.classList.add("open");
  const enabled = window._settings.ai_enabled === "1";
  const noKeyMsg = document.getElementById("ai-modal-nokey");
  const chatWrap = document.getElementById("ai-modal-chat-wrap");
  if (enabled) {
    if (noKeyMsg) noKeyMsg.style.display = "none";
    if (chatWrap) chatWrap.style.display = "flex";
  } else {
    if (noKeyMsg) noKeyMsg.style.display = "block";
    if (chatWrap) chatWrap.style.display = "none";
  }
  _renderIntroChips();
};

window.closeAIModal = function() {
  document.getElementById("ai-modal")?.classList.remove("open");
};

window.closeAIModalOnOverlay = function(e) {
  if (e.target.id === "ai-modal") window.closeAIModal();
};

// ── Rich AI message rendering helpers (chip buttons, account cards, confirm) ──

function _aiFormatText(t) {
  // Allow lightweight **bold** and line breaks; everything else is escaped.
  const esc = escHtml(String(t || ""));
  return esc.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/\n/g, "<br>");
}

function _aiPlatformInitial(p) {
  return (getPlatformLabel(p) || "?").slice(0, 2).toUpperCase();
}

function _aiRenderStats(stats) {
  const wrap = document.createElement("div");
  wrap.className = "ai-stat-grid";
  stats.forEach(s => {
    const cell = document.createElement("div");
    cell.className = `ai-stat-cell ${s.color || ""}`;
    cell.innerHTML = `<div class="ai-stat-val">${escHtml(String(s.value))}</div><div class="ai-stat-lbl">${escHtml(s.label)}</div>`;
    wrap.appendChild(cell);
  });
  return wrap;
}

function _aiRenderAccountList(accounts, moreCount) {
  const wrap = document.createElement("div");
  wrap.className = "ai-acct-list";
  accounts.forEach(a => {
    const row = document.createElement("div");
    row.className = `ai-acct-card status-${a.status}`;
    const color = getPlatformColor(a.platform);
    row.innerHTML = `
      <div class="ai-acct-avatar" style="background:${color}1f;color:${color};border-color:${color}55;">${_aiPlatformInitial(a.platform)}</div>
      <div class="ai-acct-info">
        <div class="ai-acct-name">${escHtml(a.name)}</div>
        <div class="ai-acct-sub">
          <span class="ai-acct-pill" style="background:${color}1a;color:${color};">${escHtml(a.platformLabel)}</span>
          ${a.sub ? `<span class="ai-acct-meta">${escHtml(a.sub)}</span>` : ""}
        </div>
      </div>
      <div class="ai-acct-side">
        <span class="ai-acct-status status-${a.status}">${escHtml(a.status)}</span>
        <div class="ai-acct-flags">
          ${a.twoFa ? `<span title="2FA on" class="ai-flag good">2FA</span>` : `<span title="No 2FA" class="ai-flag warn">No 2FA</span>`}
          ${a.weak ? `<span title="Weak password" class="ai-flag bad">Weak</span>` : ""}
        </div>
      </div>
    `;
    wrap.appendChild(row);
  });
  if (moreCount > 0) {
    const more = document.createElement("div");
    more.className = "ai-acct-more";
    more.textContent = `+ ${moreCount} more`;
    wrap.appendChild(more);
  }
  return wrap;
}

function _aiRenderActions(actions) {
  const wrap = document.createElement("div");
  wrap.className = "ai-action-chips";
  actions.forEach(a => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `ai-chip ${a.style || ""}`;
    btn.innerHTML = `${a.icon ? `<span class="ai-chip-ico">${a.icon}</span>` : ""}<span>${escHtml(a.label)}</span>`;
    btn.addEventListener("click", () => window.aiSendCmd(a.cmd));
    wrap.appendChild(btn);
  });
  return wrap;
}

// Animated security-score gauge — shows 0-100 with grade badge.
function _aiRenderScoreGauge(s) {
  const wrap = document.createElement("div");
  wrap.className = `ai-score-card color-${s.color}`;
  const angle = Math.max(0, Math.min(100, s.score)) * 3.6; // deg
  wrap.innerHTML = `
    <div class="ai-score-ring" style="background: conic-gradient(var(--c) ${angle}deg, rgba(255,255,255,0.08) ${angle}deg);">
      <div class="ai-score-ring-inner">
        <div class="ai-score-num">${s.score}</div>
        <div class="ai-score-grade">${escHtml(s.grade)}</div>
      </div>
    </div>
    <div class="ai-score-side">
      <div class="ai-score-row"><span>Weak</span><b>${s.weak}</b></div>
      <div class="ai-score-row"><span>No 2FA</span><b>${s.noTfa}</b></div>
      <div class="ai-score-row"><span>Dead</span><b>${s.dead}</b></div>
      <div class="ai-score-row"><span>Missing pwd</span><b>${s.missingPwd}</b></div>
      <div class="ai-score-row"><span>Missing email</span><b>${s.missingEmail}</b></div>
    </div>`;
  return wrap;
}

// Horizontal mini bars for platform breakdown / counts.
function _aiRenderBars(items, total) {
  const wrap = document.createElement("div");
  wrap.className = "ai-bars";
  const max = Math.max(1, ...items.map(i => i.count));
  items.forEach(it => {
    const pct = Math.max(2, Math.round((it.count / max) * 100));
    const share = total ? Math.round((it.count / total) * 100) : 0;
    const row = document.createElement("div");
    row.className = "ai-bar-row";
    row.innerHTML = `
      <div class="ai-bar-label">
        <span class="ai-bar-dot" style="background:${it.color || "#64748b"};"></span>
        <span class="ai-bar-name">${escHtml(it.label || it.platform)}</span>
        <span class="ai-bar-count">${it.count}${share ? ` · ${share}%` : ""}</span>
      </div>
      <div class="ai-bar-track"><div class="ai-bar-fill" style="width:${pct}%;background:${it.color || "#64748b"};"></div></div>`;
    wrap.appendChild(row);
  });
  return wrap;
}

// Pretty timeline of recent log entries.
function _aiRenderTimeline(entries) {
  const wrap = document.createElement("div");
  wrap.className = "ai-timeline";
  entries.forEach(e => {
    const row = document.createElement("div");
    row.className = `ai-tl-row act-${e.action || "info"}`;
    const when = e.ts ? new Date(e.ts).toLocaleString() : "—";
    row.innerHTML = `
      <div class="ai-tl-dot"></div>
      <div class="ai-tl-body">
        <div class="ai-tl-head">
          <span class="ai-tl-action">${escHtml(e.action || "event")}</span>
          <span class="ai-tl-time">${escHtml(when)}</span>
        </div>
        <div class="ai-tl-msg">${escHtml(e.message || e.target || "")}</div>
      </div>`;
    wrap.appendChild(row);
  });
  return wrap;
}

// Status pills row for "system status".
function _aiRenderStatusPills(items) {
  const wrap = document.createElement("div");
  wrap.className = "ai-status-pills";
  items.forEach(it => {
    const p = document.createElement("div");
    p.className = `ai-status-pill ${it.ok ? "ok" : (it.warn ? "warn" : "bad")}`;
    p.innerHTML = `<span class="ai-status-dot"></span>
      <span class="ai-status-lbl">${escHtml(it.label)}</span>
      <span class="ai-status-val">${escHtml(it.value || "")}</span>`;
    wrap.appendChild(p);
  });
  return wrap;
}

function _aiRenderChallenge(challenge, msgEl) {
  const box = document.createElement("div");
  box.className = "ai-confirm-box ai-challenge-box";

  const shown = challenge.names.slice(0, 3);
  const more  = challenge.names.length - shown.length;
  const namesList = shown.map(n => `"${n}"`).join(", ") +
    (more > 0 ? ` <span style="opacity:.7">+${more} more</span>` : "");

  box.innerHTML = `
    <div class="ai-challenge-warn">
      <span class="ai-challenge-warn-ico">⚠️</span>
      <span>Type <span class="ai-challenge-code" data-role="code">${escHtml(challenge.code)}</span>
      to confirm ${namesList} will be permanently deleted.
      <strong>It can NOT be recovered!</strong></span>
    </div>
    <div class="ai-challenge-input-row">
      <input type="text" inputmode="numeric" maxlength="4" autocomplete="off"
        class="ai-challenge-input" data-role="codeInput" placeholder="••••" aria-label="Security code" />
      <button type="button" class="ai-chip danger" data-act="confirm">
        <span class="ai-chip-ico">🗑️</span> <span>Confirm delete</span>
      </button>
      <button type="button" class="ai-chip" data-act="cancel">
        <span class="ai-chip-ico">✕</span> <span>Cancel</span>
      </button>
    </div>
    <div class="ai-confirm-row" style="justify-content:flex-end;">
      <span class="ai-confirm-timer" data-role="timer"></span>
    </div>
    <div class="ai-confirm-bar"><div class="ai-confirm-bar-fill" data-role="bar"></div></div>
    <div class="ai-confirm-hint">Auto-cancels in 60 seconds. You can also type the code in the chat below.</div>
  `;

  const input = box.querySelector('[data-role="codeInput"]');
  const submit = () => {
    const v = (input.value || "").trim();
    if (v === challenge.code) {
      window.aiSendCmd(v);
    } else if (v) {
      input.classList.add("shake");
      input.setAttribute("aria-invalid", "true");
      setTimeout(() => input.classList.remove("shake"), 400);
    }
  };
  input.addEventListener("keydown", e => {
    if (e.key === "Enter") { e.preventDefault(); submit(); }
  });
  // Allow only digits
  input.addEventListener("input", () => {
    input.value = input.value.replace(/\D/g, "").slice(0, 4);
    input.removeAttribute("aria-invalid");
  });
  box.querySelector('[data-act="confirm"]').addEventListener("click", submit);
  box.querySelector('[data-act="cancel"]').addEventListener("click", () => window.aiSendCmd("no"));

  // Install pending challenge state with countdown
  _aiClearChallenge();
  const expiresAt = Date.now() + challenge.ttlMs;
  const ch = {
    code: challenge.code,
    ids: challenge.ids,
    label: challenge.label,
    names: challenge.names,
    expiresAt,
    msgEl,
    timerId: null,
  };
  const timerEl = box.querySelector('[data-role="timer"]');
  const barEl   = box.querySelector('[data-role="bar"]');
  function tick() {
    const remain = Math.max(0, expiresAt - Date.now());
    const secs = Math.ceil(remain / 1000);
    if (timerEl) timerEl.textContent = `⏳ ${secs}s`;
    if (barEl) barEl.style.width = `${Math.max(0, (remain / challenge.ttlMs) * 100)}%`;
    if (remain <= 0) {
      _aiClearChallenge();
      _aiFinalisePending(msgEl, "⌛ Auto-cancelled (timed out)");
    }
  }
  tick();
  ch.timerId = setInterval(tick, 250);
  window._aiPendingChallenge = ch;

  // Auto-focus the code input shortly after rendering
  setTimeout(() => { try { input.focus(); } catch(_){} }, 80);

  return box;
}

function _aiRenderConfirm(confirm, msgEl) {
  const box = document.createElement("div");
  box.className = "ai-confirm-box";
  box.innerHTML = `
    <div class="ai-confirm-row">
      <button type="button" class="ai-chip danger" data-act="yes">
        <span class="ai-chip-ico">✓</span> <span>Yes, delete</span>
      </button>
      <button type="button" class="ai-chip" data-act="no">
        <span class="ai-chip-ico">✕</span> <span>No, cancel</span>
      </button>
      <span class="ai-confirm-timer" data-role="timer"></span>
    </div>
    <div class="ai-confirm-bar"><div class="ai-confirm-bar-fill" data-role="bar"></div></div>
    <div class="ai-confirm-hint">Auto-cancels in 30 seconds. You can also type <strong>yes</strong> or <strong>no</strong>.</div>
  `;
  box.querySelector('[data-act="yes"]').addEventListener("click", () => window.aiSendCmd("yes"));
  box.querySelector('[data-act="no" ]').addEventListener("click", () => window.aiSendCmd("no"));

  // Install pending state with live countdown.
  _aiClearPending();
  const expiresAt = Date.now() + confirm.ttlMs;
  const pending = {
    type: confirm.type,
    ids: confirm.ids,
    label: confirm.label,
    expiresAt,
    msgEl,
    timerId: null,
  };
  const timerEl = box.querySelector('[data-role="timer"]');
  const barEl   = box.querySelector('[data-role="bar"]');

  function tick() {
    const remain = Math.max(0, expiresAt - Date.now());
    const secs = Math.ceil(remain / 1000);
    if (timerEl) timerEl.textContent = `⏳ ${secs}s`;
    if (barEl) barEl.style.width = `${Math.max(0, (remain / confirm.ttlMs) * 100)}%`;
    if (remain <= 0) {
      _aiClearPending();
      _aiFinalisePending(msgEl, "⌛ Auto-cancelled (timed out)");
    }
  }
  tick();
  pending.timerId = setInterval(tick, 250);
  window._aiPendingAction = pending;
  return box;
}

function _aiAppendBotRich(payload) {
  const container = document.getElementById("ai-modal-messages");
  if (!container) return null;
  if (typeof payload === "string") payload = { text: payload };

  const row = document.createElement("div");
  row.className = "ai-msg ai-msg-bot";
  row.innerHTML = `<div class="ai-msg-avatar">AI</div>`;

  const bubble = document.createElement("div");
  bubble.className = "ai-msg-bubble";

  if (payload.text) {
    const t = document.createElement("div");
    t.className = "ai-msg-text";
    t.innerHTML = _aiFormatText(payload.text);
    bubble.appendChild(t);
  }
  if (payload.stats)       bubble.appendChild(_aiRenderStats(payload.stats));
  if (payload.scoreGauge)  bubble.appendChild(_aiRenderScoreGauge(payload.scoreGauge));
  if (payload.bars)        bubble.appendChild(_aiRenderBars(payload.bars, payload.barsTotal || 0));
  if (payload.statusPills) bubble.appendChild(_aiRenderStatusPills(payload.statusPills));
  if (payload.timeline)    bubble.appendChild(_aiRenderTimeline(payload.timeline));
  if (payload.accounts)    bubble.appendChild(_aiRenderAccountList(payload.accounts, payload.moreCount || 0));
  if (payload.hint) {
    const h = document.createElement("div");
    h.className = "ai-msg-hint";
    h.textContent = payload.hint;
    bubble.appendChild(h);
  }
  if (payload.confirm)   bubble.appendChild(_aiRenderConfirm(payload.confirm, row));
  if (payload.challenge) bubble.appendChild(_aiRenderChallenge(payload.challenge, row));
  if (payload.actions && payload.actions.length) bubble.appendChild(_aiRenderActions(payload.actions));

  row.appendChild(bubble);
  container.appendChild(row);
  container.scrollTop = container.scrollHeight;
  return row;
}

function _aiAppendUser(text) {
  const container = document.getElementById("ai-modal-messages");
  if (!container) return null;
  const row = document.createElement("div");
  row.className = "ai-msg ai-msg-user";
  row.innerHTML = `<div class="ai-msg-bubble">${escHtml(text)}</div><div class="ai-msg-avatar">YOU</div>`;
  container.appendChild(row);
  container.scrollTop = container.scrollHeight;
  return row;
}

function appendAIModalMessage(role, payload) {
  return role === "user" ? _aiAppendUser(typeof payload === "string" ? payload : (payload && payload.text) || "")
                         : _aiAppendBotRich(payload);
}

window.aiModalChatKeydown = function(e) {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendAIModalChat();
  }
};

// Unified entry point for chip clicks and the Quick Commands sidebar.
window.aiSendCmd = function(cmd) {
  const input = document.getElementById("ai-modal-input");
  if (input) {
    input.value = cmd;
    sendAIModalChat();
  }
};
// Backwards-compat with existing onclick="aiQuickCmd('…')" attributes.
window.aiQuickCmd = function(cmd) { window.aiSendCmd(cmd); };

window.sendAIModalChat = async function() {
  const input = document.getElementById("ai-modal-input");
  const sendBtn = document.getElementById("ai-modal-send-btn");
  const text = input ? input.value.trim() : "";
  if (!text) return;

  input.value = "";
  input.disabled = true;
  if (sendBtn) sendBtn.disabled = true;

  _aiAppendUser(text);

  const thinkingDiv = document.createElement("div");
  thinkingDiv.className = "ai-msg ai-msg-bot";
  thinkingDiv.innerHTML = `<div class="ai-msg-avatar">AI</div><div class="ai-msg-bubble typing"><span class="ai-typing-dot"></span><span class="ai-typing-dot"></span><span class="ai-typing-dot"></span></div>`;
  const container = document.getElementById("ai-modal-messages");
  if (container) { container.appendChild(thinkingDiv); container.scrollTop = container.scrollHeight; }

  let directReply;
  try { directReply = await processAIDirectAction(text); }
  catch (err) { directReply = { text: "Action failed: " + err.message }; }

  if (directReply !== null && directReply !== undefined) {
    if (thinkingDiv.parentNode) thinkingDiv.parentNode.removeChild(thinkingDiv);
    _aiAppendBotRich(directReply);
    if (input) input.disabled = false;
    if (sendBtn) sendBtn.disabled = false;
    if (input) input.focus();
    return;
  }

  const provider = window._settings.ai_provider || "openai";
  const msgs = [{ role: "user", content: text }];
  try {
    let reply;
    if (provider === "gemini") {
      reply = await callGemini(msgs, "chat");
    } else {
      reply = await callOpenAI(msgs, "chat");
    }
    if (thinkingDiv.parentNode) thinkingDiv.parentNode.removeChild(thinkingDiv);
    _aiAppendBotRich({
      text: reply,
      actions: [{ label: "What else can you do?", cmd: "help", icon: "💡" }],
    });
  } catch (err) {
    if (thinkingDiv.parentNode) thinkingDiv.parentNode.removeChild(thinkingDiv);
    _aiAppendBotRich({ text: "Error: " + err.message });
  }

  if (input) input.disabled = false;
  if (sendBtn) sendBtn.disabled = false;
  if (input) input.focus();
};

// ── ANALYTICS ──
window.openAnalytics = function() {
  if (isMobile()) closeSidebar();
  renderAnalytics();
  document.getElementById("analytics-modal").classList.add("open");
};

// ── SYSTEM HEALTH ──
// Live status of: backend endpoints, Firebase auth/db, browser env, recent
// errors, recent vault updates. Pure read-only — no writes.
window.openSystemHealth = function() {
  if (isMobile()) closeSidebar();
  document.getElementById("system-health-modal").classList.add("open");
  renderSystemHealth();
};

async function _syshProbe(path) {
  const t0 = performance.now();
  try {
    const r = await fetch(path, { cache: "no-store", credentials: "same-origin" });
    const ms = Math.round(performance.now() - t0);
    let body = null; try { body = await r.json(); } catch(_) {}
    return {
      ok: r.ok && (!body || body.ok !== false),
      status: r.status,
      ms,
      detail: body && (body.error || body.status) || (r.ok ? "OK" : "Failed"),
    };
  } catch (e) {
    return { ok: false, status: 0, ms: Math.round(performance.now() - t0), detail: e && e.message || String(e) };
  }
}

function _syshFmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  const diff = Math.max(0, Date.now() - ts);
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec/60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec/3600)}h ago`;
  return d.toLocaleString();
}

function _syshRow(label, ok, detail, extra) {
  const row = document.createElement("div");
  row.className = "sysh-row";
  const dot = document.createElement("span");
  dot.className = "sysh-dot " + (ok === null ? "pending" : ok ? "ok" : "bad");
  const lab = document.createElement("div"); lab.className = "sysh-label"; lab.textContent = label;
  const det = document.createElement("div"); det.className = "sysh-detail"; det.textContent = detail || "";
  const ext = document.createElement("div"); ext.className = "sysh-extra";  ext.textContent = extra  || "";
  row.append(dot, lab, det, ext);
  return row;
}

function _syshSection(title, icon, rowsBuilder) {
  const card = document.createElement("div");
  card.className = "sysh-card";
  const head = document.createElement("div");
  head.className = "sysh-card-head";
  head.innerHTML = `<span class="sysh-card-ico">${icon}</span><span>${escHtml(title)}</span>`;
  card.appendChild(head);
  const body = document.createElement("div");
  body.className = "sysh-card-body";
  rowsBuilder(body);
  card.appendChild(body);
  return card;
}

window.renderSystemHealth = async function() {
  const body = document.getElementById("sysh-body");
  const sub  = document.getElementById("sysh-sub");
  if (!body) return;
  body.replaceChildren();
  if (sub) sub.textContent = `Running checks · ${new Date().toLocaleTimeString()}`;

  // Skeleton container
  const grid = document.createElement("div");
  grid.className = "sysh-grid";
  body.appendChild(grid);

  // ── Top stat tiles ──
  const tiles = document.createElement("div");
  tiles.className = "sysh-tiles";
  function tile(color, label, value, sub) {
    const t = document.createElement("div");
    t.className = `sysh-tile ${color}`;
    t.innerHTML = `<div class="sysh-tile-lbl">${escHtml(label)}</div><div class="sysh-tile-val" data-role="val">${escHtml(value)}</div><div class="sysh-tile-sub" data-role="sub">${escHtml(sub || "")}</div>`;
    return t;
  }
  const wb = window.VaultBackend && window.VaultBackend.status || {};
  const onlineTile = tile(wb.online ? "green" : "red", "Backend", wb.online ? "Online" : "Offline", `${wb.latencyMs || 0}ms · ${_syshFmtTime(wb.lastOk)}`);
  const errsTile   = tile("red",  "Errors",  String(VaultDebug._getErrors().filter(e=>e.level==="error").length), "Captured this session");
  const warnsTile  = tile("yellow","Warnings", String(VaultDebug._getErrors().filter(e=>e.level==="warn").length), "Captured this session");
  const acctTile   = tile("blue", "Accounts", String((window.allAccounts || []).length), "Loaded in vault");
  tiles.append(onlineTile, errsTile, warnsTile, acctTile);
  grid.appendChild(tiles);

  // ── Backend endpoints ──
  const beCard = _syshSection("Backend Endpoints", "🛰️", (b) => {
    b.appendChild(_syshRow("/api/config",   null, "checking…", ""));
    b.appendChild(_syshRow("/api/watchdog", null, "checking…", ""));
    b.appendChild(_syshRow("/api/health",   null, "checking…", ""));
  });
  grid.appendChild(beCard);

  // ── Firebase status ──
  const fbCard = _syshSection("Firebase Connection", "🔥", (b) => {
    b.appendChild(_syshRow("Auth state",   null, "checking…", ""));
    b.appendChild(_syshRow("RTDB read",    null, "checking…", ""));
    b.appendChild(_syshRow("Project ID",   true, FIREBASE_CFG && FIREBASE_CFG.projectId || "—", ""));
  });
  grid.appendChild(fbCard);

  // ── Environment ──
  const envCard = _syshSection("Environment", "💻", (b) => {
    const ua = navigator.userAgent || "";
    const browser = /Chrome\/[\d.]+/.exec(ua)?.[0] || /Firefox\/[\d.]+/.exec(ua)?.[0] || /Safari\/[\d.]+/.exec(ua)?.[0] || "Unknown";
    const memory = (navigator.deviceMemory ? navigator.deviceMemory + " GB" : "n/a");
    b.appendChild(_syshRow("Page",       true, location.host, location.protocol));
    b.appendChild(_syshRow("Browser",    true, browser, navigator.platform || ""));
    b.appendChild(_syshRow("Online",     navigator.onLine, navigator.onLine ? "Connected" : "Disconnected", ""));
    b.appendChild(_syshRow("Screen",     true, `${screen.width}×${screen.height}`, `DPR ${window.devicePixelRatio || 1}`));
    b.appendChild(_syshRow("Locale",     true, (navigator.language || ""), Intl.DateTimeFormat().resolvedOptions().timeZone || ""));
    b.appendChild(_syshRow("Memory",     true, memory, navigator.hardwareConcurrency ? `${navigator.hardwareConcurrency} cores` : ""));
    b.appendChild(_syshRow("Secure ctx", window.isSecureContext, window.isSecureContext ? "HTTPS / localhost" : "Insecure", ""));
  });
  grid.appendChild(envCard);

  // ── Recent errors ──
  const errCard = _syshSection("Recent Errors & Warnings", "⚠️", (b) => {
    const errs = VaultDebug._getErrors().slice(-12).reverse();
    if (!errs.length) {
      const empty = document.createElement("div");
      empty.className = "sysh-empty";
      empty.textContent = "No errors captured this session ✓";
      b.appendChild(empty);
      return;
    }
    errs.forEach(e => {
      const r = document.createElement("div");
      r.className = "sysh-err " + (e.level === "error" ? "bad" : "warn");
      r.innerHTML = `<span class="sysh-err-time">${escHtml(e.time)}</span><span class="sysh-err-tag">${escHtml(e.level.toUpperCase())}</span><span class="sysh-err-msg"></span>`;
      r.querySelector(".sysh-err-msg").textContent = e.msg;
      b.appendChild(r);
    });
  });
  grid.appendChild(errCard);

  // ── Recent vault updates ──
  const updCard = _syshSection("Recent Vault Updates", "🔄", (b) => {
    const ph = document.createElement("div");
    ph.className = "sysh-empty";
    ph.textContent = "Loading update log…";
    b.appendChild(ph);
  });
  grid.appendChild(updCard);

  // ── Security posture ──
  const secCard = _syshSection("Security Posture", "🛡️", (b) => {
    const httpsOk = location.protocol === "https:" || /^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/.test(location.hostname);
    const beLock  = !!(window.VaultBackend && window.VaultBackend.status.online);
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    const xframe  = !!document.querySelector('meta[http-equiv="X-Frame-Options"]');
    b.appendChild(_syshRow("HTTPS / secure",   httpsOk, httpsOk ? "Enabled" : "Insecure", ""));
    b.appendChild(_syshRow("Backend gated",    beLock,  beLock ? "Locks if backend down" : "Disconnected", ""));
    b.appendChild(_syshRow("Domain allow-list", true,   "Enforced server-side", ""));
    b.appendChild(_syshRow("Rate limiter",     true,    "60 req / min / IP", ""));
    b.appendChild(_syshRow("CSP meta",         !!cspMeta, cspMeta ? "Present" : "Header-only", ""));
    b.appendChild(_syshRow("X-Frame-Options",  true,    "SAMEORIGIN (server)", ""));
  });
  grid.appendChild(secCard);

  // ── Run probes in parallel ──
  const [pCfg, pWd, pHl] = await Promise.all([
    _syshProbe("/api/config"),
    _syshProbe("/api/watchdog"),
    _syshProbe("/api/health"),
  ]);
  const beRows = beCard.querySelectorAll(".sysh-row");
  function fillProbe(row, p) {
    const dot = row.children[0];
    dot.classList.remove("pending");
    dot.classList.add(p.ok ? "ok" : "bad");
    row.children[2].textContent = `${p.status || "—"} · ${p.detail}`;
    row.children[3].textContent = `${p.ms}ms`;
  }
  fillProbe(beRows[0], pCfg);
  fillProbe(beRows[1], pWd);
  fillProbe(beRows[2], pHl);

  // ── Firebase probes ──
  const fbRows = fbCard.querySelectorAll(".sysh-row");
  const authOk = !!(auth && auth.currentUser);
  const authRow = fbRows[0];
  authRow.children[0].classList.remove("pending");
  authRow.children[0].classList.add(authOk ? "ok" : "warn");
  authRow.children[2].textContent = authOk ? `Signed in · ${auth.currentUser.email || "user"}` : "Not signed in";
  authRow.children[3].textContent = "";
  try {
    const t0 = performance.now();
    await new Promise((res, rej) => {
      const t = setTimeout(() => rej(new Error("timeout")), 6000);
      onValue(ref(db, ".info/connected"), snap => { clearTimeout(t); res(snap.val()); }, rej, { onlyOnce: true });
    });
    const ms = Math.round(performance.now() - t0);
    fbRows[1].children[0].classList.remove("pending");
    fbRows[1].children[0].classList.add("ok");
    fbRows[1].children[2].textContent = "Connected to RTDB";
    fbRows[1].children[3].textContent = `${ms}ms`;
  } catch (e) {
    fbRows[1].children[0].classList.remove("pending");
    fbRows[1].children[0].classList.add("bad");
    fbRows[1].children[2].textContent = e && e.message || "Failed";
  }

  // ── Vault updates feed ──
  try {
    const snap = await new Promise((res, rej) => onValue(ref(db, LOG_COLLECTION), res, rej, { onlyOnce: true }));
    const raw = snap.val() || {};
    const logs = Object.entries(raw)
      .map(([id, v]) => ({ id, ...v }))
      .sort((a, b) => (b.timestamp||0) - (a.timestamp||0))
      .slice(0, 8);
    const cont = updCard.querySelector(".sysh-card-body");
    cont.replaceChildren();
    if (!logs.length) {
      const empty = document.createElement("div");
      empty.className = "sysh-empty";
      empty.textContent = "No vault updates yet";
      cont.appendChild(empty);
    } else {
      logs.forEach(l => {
        const r = document.createElement("div");
        r.className = "sysh-upd";
        const tm = new Date(l.timestamp || 0);
        r.innerHTML = `<span class="sysh-upd-tag">${escHtml(l.type || "event")}</span>
                       <span class="sysh-upd-msg"></span>
                       <span class="sysh-upd-time">${escHtml(_syshFmtTime(l.timestamp))}</span>`;
        r.querySelector(".sysh-upd-msg").textContent = (l.label || l.detail || l.message || "").slice(0, 120);
        cont.appendChild(r);
      });
    }
  } catch (e) {
    const cont = updCard.querySelector(".sysh-card-body");
    cont.replaceChildren();
    const err = document.createElement("div");
    err.className = "sysh-empty bad";
    err.textContent = "Could not load updates: " + (e && e.message || String(e));
    cont.appendChild(err);
  }

  // Refresh top tile values now that probes finished
  const wb2 = window.VaultBackend && window.VaultBackend.status || {};
  onlineTile.classList.remove("red", "green");
  onlineTile.classList.add(wb2.online ? "green" : "red");
  onlineTile.querySelector('[data-role="val"]').textContent = wb2.online ? "Online" : "Offline";
  onlineTile.querySelector('[data-role="sub"]').textContent = `${wb2.latencyMs || 0}ms · ${_syshFmtTime(wb2.lastOk)}`;

  if (sub) sub.textContent = `All checks complete · ${new Date().toLocaleTimeString()}`;
};

function renderAnalytics() {
  const body = document.getElementById("analytics-body");
  if (!body) return;

  const total    = allAccounts.length;
  const live     = allAccounts.filter(a => a.status === "live").length;
  const dead     = allAccounts.filter(a => a.status === "dead").length;
  const unknown  = total - live - dead;
  const liveP    = total ? Math.round((live / total) * 100) : 0;
  const deadP    = total ? Math.round((dead / total) * 100) : 0;
  const noTFA    = allAccounts.filter(a => !a.twoFaKey).length;
  const hasTFA   = total - noTFA;
  const weakPw   = allAccounts.filter(a => isWeakPassword(a.password)).length;
  const withNote = allAccounts.filter(a => a.note).length;
  const withImg  = allAccounts.filter(a => a.imageUrl).length;
  const score    = total === 0 ? 0 : Math.max(0, Math.round(100 - (noTFA/total)*40 - (weakPw/total)*40 - ((total-withImg)/total)*10 - ((total-withNote)/total)*10));
  const scoreColor = score >= 80 ? "var(--green)" : score >= 50 ? "var(--yellow)" : "var(--red)";

  // Platform breakdown
  const platformCounts = {};
  allAccounts.forEach(a => {
    const p = a.platform || "other";
    platformCounts[p] = (platformCounts[p] || 0) + 1;
  });
  const platforms = Object.entries(platformCounts).sort((a,b) => b[1]-a[1]);
  const maxP = platforms[0]?.[1] || 1;

  // Recent accounts (last 5)
  const recent = [...allAccounts]
    .filter(a => a.createdAt)
    .sort((a,b) => (b.createdAt||0) - (a.createdAt||0))
    .slice(0, 5);
  const recentFallback = recent.length === 0 ? [...allAccounts].slice(-5).reverse() : recent;

  const getPlatformEmoji = (p) => ({
    facebook:"🔵",instagram:"🟣",gmail:"🔴",twitter:"🐦",tiktok:"⚫",
    snapchat:"🟡",discord:"🟣",telegram:"🔵",whatsapp:"🟢",youtube:"🔴",linkedin:"🔵"
  }[p] || "⚪");

  // Update subtitle
  const sub = document.getElementById("analytics-fp-sub");
  if (sub) sub.textContent = `${total} accounts · Updated ${new Date().toLocaleTimeString()}`;

  body.innerHTML = `
    <!-- Top stat cards -->
    <div class="analytics-fp-grid">
      <div class="analytics-fp-stat blue">
        <div class="analytics-fp-stat-label">Total Accounts</div>
        <div class="analytics-fp-stat-value">${total}</div>
        <div class="analytics-fp-stat-sub">${live} live · ${dead} dead</div>
      </div>
      <div class="analytics-fp-stat green">
        <div class="analytics-fp-stat-label">Live Accounts</div>
        <div class="analytics-fp-stat-value">${live}</div>
        <div class="analytics-fp-stat-sub">${liveP}% of total</div>
      </div>
      <div class="analytics-fp-stat red">
        <div class="analytics-fp-stat-label">Dead Accounts</div>
        <div class="analytics-fp-stat-value">${dead}</div>
        <div class="analytics-fp-stat-sub">${deadP}% of total</div>
      </div>
      <div class="analytics-fp-stat purple">
        <div class="analytics-fp-stat-label">Security Score</div>
        <div class="analytics-fp-stat-value" style="color:${scoreColor};">${total===0?"—":score+"%"}</div>
        <div class="analytics-fp-stat-sub">${score>=80?"Excellent":score>=60?"Good":score>=40?"Fair":"Needs work"}</div>
      </div>
    </div>

    <!-- Row 1: Live/Dead ratio + 2FA coverage -->
    <div class="analytics-fp-row">
      <div class="analytics-fp-card">
        <div class="analytics-fp-card-header">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          Live vs Dead Ratio
        </div>
        <div class="analytics-fp-card-body">
          <div style="display:flex;justify-content:space-between;margin-bottom:8px;font-size:12px;">
            <span style="color:var(--green);">● Live — ${live} (${liveP}%)</span>
            <span style="color:var(--red);">● Dead — ${dead} (${deadP}%)</span>
          </div>
          <div class="analytics-2fa-bar">
            <div class="analytics-2fa-yes" style="width:${liveP}%;"></div>
            <div class="analytics-2fa-no"  style="width:${deadP}%;"></div>
            ${unknown>0?`<div style="flex:1;background:var(--border);"></div>`:""}
          </div>
          <div style="font-size:11px;color:var(--text3);margin-top:8px;">
            ${unknown>0?`${unknown} accounts have no status set`:liveP>=50?"More than half your accounts are active":"Most accounts are dead"}
          </div>
        </div>
      </div>

      <div class="analytics-fp-card">
        <div class="analytics-fp-card-header">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
          2FA Coverage
        </div>
        <div class="analytics-fp-card-body">
          <div style="display:flex;justify-content:space-between;margin-bottom:8px;font-size:12px;">
            <span style="color:var(--green);">● With 2FA — ${hasTFA}</span>
            <span style="color:var(--red);">● No 2FA — ${noTFA}</span>
          </div>
          <div class="analytics-2fa-bar">
            <div class="analytics-2fa-yes" style="width:${total?Math.round((hasTFA/total)*100):0}%;"></div>
            <div class="analytics-2fa-no"  style="width:${total?Math.round((noTFA/total)*100):0}%;"></div>
          </div>
          <div style="font-size:11px;color:var(--text3);margin-top:8px;">
            ${noTFA===0?"All accounts protected with 2FA ✓":`${noTFA} account${noTFA>1?"s":""} missing 2FA protection`}
          </div>
        </div>
      </div>
    </div>

    <!-- Row 2: Platform breakdown + Security -->
    <div class="analytics-fp-row">
      <div class="analytics-fp-card">
        <div class="analytics-fp-card-header">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
          Platform Distribution
        </div>
        <div class="analytics-fp-card-body">
          ${platforms.length === 0
            ? `<div style="color:var(--text3);font-size:13px;text-align:center;padding:20px 0;">No accounts yet</div>`
            : platforms.slice(0,8).map(([p, count]) => `
              <div class="analytics-platform-bar">
                <span class="analytics-platform-name">${getPlatformEmoji(p)} ${getPlatformLabel(p)}</span>
                <div class="analytics-platform-track">
                  <div class="analytics-platform-fill" style="width:${Math.round((count/maxP)*100)}%;"></div>
                </div>
                <span class="analytics-platform-pct">${count}</span>
              </div>`).join("")}
        </div>
      </div>

      <div class="analytics-fp-card">
        <div class="analytics-fp-card-header">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Security Issues
        </div>
        <div class="analytics-fp-card-body">
          <div class="analytics-security-item">
            <div class="analytics-sec-icon" style="background:${noTFA>0?'rgba(239,68,68,0.12)':'rgba(34,197,94,0.12)'};color:${noTFA>0?'var(--red)':'var(--green)'};">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
            </div>
            <div class="analytics-sec-info">
              <div class="analytics-sec-title">No 2FA</div>
              <div class="analytics-sec-desc">${noTFA>0?"At risk — no two-factor auth":"All protected ✓"}</div>
            </div>
            <div class="analytics-sec-badge" style="color:${noTFA>0?'var(--red)':'var(--green)'};">${noTFA}</div>
          </div>
          <div class="analytics-security-item">
            <div class="analytics-sec-icon" style="background:${weakPw>0?'rgba(239,68,68,0.12)':'rgba(34,197,94,0.12)'};color:${weakPw>0?'var(--red)':'var(--green)'};">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
            </div>
            <div class="analytics-sec-info">
              <div class="analytics-sec-title">Weak Passwords</div>
              <div class="analytics-sec-desc">${weakPw>0?"Passwords shorter than 8 chars":"All passwords strong ✓"}</div>
            </div>
            <div class="analytics-sec-badge" style="color:${weakPw>0?'var(--red)':'var(--green)'};">${weakPw}</div>
          </div>
          <div class="analytics-security-item">
            <div class="analytics-sec-icon" style="background:${withNote>0?'rgba(34,197,94,0.12)':'rgba(245,158,11,0.12)'};color:${withNote>0?'var(--green)':'var(--yellow)'};">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            </div>
            <div class="analytics-sec-info">
              <div class="analytics-sec-title">Have Notes</div>
              <div class="analytics-sec-desc">Accounts with extra info</div>
            </div>
            <div class="analytics-sec-badge" style="color:var(--cyan);">${withNote}</div>
          </div>
          <div class="analytics-security-item">
            <div class="analytics-sec-icon" style="background:rgba(59,130,246,0.12);color:var(--primary);">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/></svg>
            </div>
            <div class="analytics-sec-info">
              <div class="analytics-sec-title">Have Profile Photo</div>
              <div class="analytics-sec-desc">Accounts with uploaded image</div>
            </div>
            <div class="analytics-sec-badge" style="color:var(--primary);">${withImg}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Row 3: Recent accounts (full width) -->
    ${recentFallback.length > 0 ? `
    <div class="analytics-fp-row">
      <div class="analytics-fp-card full">
        <div class="analytics-fp-card-header">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          Recent Accounts
        </div>
        <div class="analytics-fp-card-body">
          ${recentFallback.map(a => `
            <div class="analytics-recent-row">
              <div class="analytics-recent-icon">${getPlatformEmoji(a.platform)}</div>
              <div style="flex:1;min-width:0;">
                <div class="analytics-recent-name">${escHtml(a.name || "Unnamed")}</div>
                <div class="analytics-recent-plat">${getPlatformLabel(a.platform || "other")} ${a.email ? "· "+escHtml(a.email) : ""}</div>
              </div>
              <span class="analytics-recent-status ${a.status||'unknown'}">${a.status||"—"}</span>
            </div>`).join("")}
        </div>
      </div>
    </div>` : ""}
  `;
}



function runWeakSecurityScan() {
  if (_weakAlertShown) return;
  const banner = document.getElementById("weak-security-banner");
  if (!banner || !allAccounts.length) return;

  const weakPw  = allAccounts.filter(a => isWeakPassword(a.password));
  const noTFA   = allAccounts.filter(a => !a.twoFaKey);
  const issues  = [];
  if (weakPw.length)  issues.push(`${weakPw.length} weak password${weakPw.length>1?"s":""}`);
  if (noTFA.length)   issues.push(`${noTFA.length} account${noTFA.length>1?"s":""} without 2FA`);

  if (issues.length === 0) { banner.classList.remove("visible"); return; }

  document.getElementById("weak-alert-title").textContent = "Security Issues Detected";
  document.getElementById("weak-alert-detail").textContent = issues.join(" · ");
  banner.classList.add("visible");
  _weakAlertShown = true;
}

window.dismissWeakAlert = function() {
  const banner = document.getElementById("weak-security-banner");
  if (banner) banner.classList.remove("visible");
};

// ── BULK PARSER ──
window.openBulkParser = function() {
  if (isMobile()) closeSidebar();
  document.getElementById("bulk-parser-modal").classList.add("open");
  document.getElementById("bulk-parsed-preview").innerHTML = "";
  document.getElementById("bulk-save-btn").style.display = "none";
  document.getElementById("bulk-stats-bar").style.display = "none";
  const inp = document.getElementById("bulk-parser-input");
  if (inp) inp.value = "";
};

let _bulkParsed = [];

const _BULK_PLATFORMS = ["gmail","facebook","instagram","twitter","tiktok","snapchat",
  "youtube","discord","telegram","github","linkedin","reddit","netflix","amazon",
  "apple","spotify","paypal","binance","coinbase","steam","epic","roblox",
  "minecraft","whatsapp","pinterest","twitch","dropbox","adobe","zoom","other"];

function _parseBulkLine(line) {
  const acc = { platform:"other", name:"", email:"", uid:"", number:"", password:"", twoFaKey:"", status:"live", note:"", _valid:false };

  // ── Format 1: key: value | key: value (pipe-separated key:value pairs) ──
  if (/\|/.test(line)) {
    const parts = line.split("|").map(s => s.trim());
    parts.forEach((seg, i) => {
      const ci = seg.indexOf(":");
      if (ci === -1) {
        // No colon — positional (email|password pattern)
        if (i === 1 && !acc.email && seg) { acc.email = seg; acc.name = acc.name || seg; }
        if (i === 2 && !acc.password && seg) acc.password = seg;
        return;
      }
      const k = seg.slice(0, ci).trim().toLowerCase();
      const v = seg.slice(ci + 1).trim();
      if (!v) return;
      if (i === 0 && !["pass","password","email","user","uid","2fa","phone","number","note","name","status","dob"].includes(k)) {
        const pl = _BULK_PLATFORMS.find(p => k.includes(p));
        acc.platform = pl || k.replace(/[^a-z0-9]/g,"") || "other";
        if (v.includes("@")) { acc.email = v; acc.name = acc.name || v; }
        else { acc.uid = v; acc.name = acc.name || v; }
        acc._valid = !!v;
      } else if (["pass","password","pw"].includes(k)) { acc.password = v; }
      else if (k === "email" || k === "mail") { acc.email = v; if (!acc.name) acc.name = v; acc._valid = true; }
      else if (["user","uid","username","id"].includes(k)) { acc.uid = v; if (!acc.name) acc.name = v; acc._valid = true; }
      else if (["2fa","totp","otp","secret"].includes(k)) { acc.twoFaKey = v; }
      else if (["phone","number","mobile","num"].includes(k)) { acc.number = v; }
      else if (k === "status") { acc.status = v === "dead" ? "dead" : "live"; }
      else if (k === "note" || k === "notes") { acc.note = v; }
      else if (k === "name") { acc.name = v; }
      else if (k === "platform" || k === "site") {
        const pl = _BULK_PLATFORMS.find(p => v.toLowerCase().includes(p));
        acc.platform = pl || v.toLowerCase().replace(/[^a-z0-9]/g,"") || "other";
      }
    });
    return acc;
  }

  // ── Format 2: email:password (simple colon, no pipe) ──
  const colonMatch = line.match(/^([^:]+):(.+)$/);
  if (colonMatch) {
    const left = colonMatch[1].trim();
    const right = colonMatch[2].trim();
    // If left looks like an email
    if (left.includes("@")) {
      acc.email = left; acc.password = right; acc.name = left; acc._valid = true;
      // Try to detect platform from email domain
      const domain = left.split("@")[1] || "";
      const pl = _BULK_PLATFORMS.find(p => domain.includes(p));
      if (pl) acc.platform = pl;
    } else {
      // left might be platform, right might be more data
      const pl = _BULK_PLATFORMS.find(p => left.toLowerCase().includes(p));
      if (pl) { acc.platform = pl; acc.uid = right; acc.name = right; acc._valid = true; }
      else { acc.uid = left; acc.password = right; acc.name = left; acc._valid = true; }
    }
    return acc;
  }

  return acc;
}

window.parseBulkAccounts = function() {
  const text = document.getElementById("bulk-parser-input").value.trim();
  const lines = text.split("\n").map(l => l.trim()).filter(Boolean);
  _bulkParsed = [];

  lines.forEach(line => {
    const result = _parseBulkLine(line);
    _bulkParsed.push(result);
  });

  const preview = document.getElementById("bulk-parsed-preview");
  const saveBtn = document.getElementById("bulk-save-btn");
  const statsBar = document.getElementById("bulk-stats-bar");

  if (!_bulkParsed.length) {
    preview.innerHTML = `<div class="bulk-empty-state"><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><span>No valid entries found. Check the format guide.</span></div>`;
    saveBtn.style.display = "none";
    if (statsBar) statsBar.style.display = "none";
    return;
  }

  const readyCount = _bulkParsed.filter(a => a._valid).length;
  const partialCount = _bulkParsed.length - readyCount;

  if (statsBar) {
    statsBar.style.display = "flex";
    statsBar.innerHTML = `
      <span class="bulk-stat"><span class="bulk-stat-num">${_bulkParsed.length}</span> parsed</span>
      <span class="bulk-stat-dot">·</span>
      <span class="bulk-stat ready"><span class="bulk-stat-num">${readyCount}</span> ready</span>
      ${partialCount > 0 ? `<span class="bulk-stat-dot">·</span><span class="bulk-stat partial"><span class="bulk-stat-num">${partialCount}</span> partial</span>` : ""}
    `;
  }

  preview.innerHTML = _bulkParsed.map((acc, i) => {
    const plColor = getPlatformColor(acc.platform);
    const plLabel = getPlatformLabel(acc.platform);
    const initials = plLabel.slice(0,2).toUpperCase();
    const displayName = acc.name || acc.email || acc.uid || "Unnamed";
    const hasPass = !!acc.password;
    const has2FA  = !!acc.twoFaKey;
    const hasEmail = !!acc.email;
    const hasUID  = !!acc.uid;
    return `
      <div class="bulk-parsed-item ${acc._valid ? "" : "partial"}">
        <div class="bulk-parsed-platform" style="background:${plColor}20;color:${plColor};border-color:${plColor}40;">${initials}</div>
        <div class="bulk-parsed-info">
          <div class="bulk-parsed-name">${escHtml(displayName)}</div>
          <div class="bulk-parsed-meta">
            <span class="bulk-pl-badge" style="color:${plColor};">${escHtml(plLabel)}</span>
            ${hasEmail ? `<span class="bulk-field-tag">📧 ${escHtml(acc.email)}</span>` : ""}
            ${hasUID && !hasEmail ? `<span class="bulk-field-tag">🔑 ${escHtml(acc.uid)}</span>` : ""}
            ${hasPass ? `<span class="bulk-field-tag">🔒 ${"•".repeat(Math.min(acc.password.length, 10))}</span>` : `<span class="bulk-field-tag missing">⚠ No password</span>`}
            ${has2FA  ? `<span class="bulk-field-tag ok">🔐 2FA</span>` : ""}
            ${acc.number ? `<span class="bulk-field-tag">📱 ${escHtml(acc.number)}</span>` : ""}
          </div>
        </div>
        <span class="bulk-parsed-status ${acc._valid ? "ready" : "partial"}">${acc._valid ? "✓ READY" : "~ PARTIAL"}</span>
      </div>
    `;
  }).join("");

  saveBtn.style.display = "inline-flex";
};

window.clearBulkParser = function() {
  _bulkParsed = [];
  document.getElementById("bulk-parser-input").value = "";
  document.getElementById("bulk-parsed-preview").innerHTML = "";
  document.getElementById("bulk-save-btn").style.display = "none";
  const statsBar = document.getElementById("bulk-stats-bar");
  if (statsBar) statsBar.style.display = "none";
};

window.saveBulkParsed = async function() {
  if (!_bulkParsed.length) return;
  const saveBtn = document.getElementById("bulk-save-btn");
  saveBtn.disabled = true;
  saveBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/></svg> Saving...`;

  let saved = 0, failed = 0;
  const now = Date.now();
  for (const acc of _bulkParsed) {
    const data = {
      platform: acc.platform || "other",
      name: acc.name || acc.email || acc.uid || "Imported Account",
      uid: acc.uid || "",
      email: acc.email || "",
      number: acc.number || "",
      password: acc.password || "",
      twoFaKey: acc.twoFaKey || "",
      status: acc.status || "live",
      note: acc.note || (acc.twoFaKey ? "" : "⚠️ No 2FA – add 2FA for better security"),
      createdAt: now,
      updatedAt: now
    };
    try {
      await push(ref(db, ADMIN_COLLECTION), data);
      saved++;
    } catch { failed++; }
  }

  if (saved > 0) {
    addVaultLog("bulk_added", `${saved} account(s)`, "other",
      `Bulk import: ${saved} saved${failed ? ", " + failed + " failed" : ""}`);
  }
  saveBtn.disabled = false;
  saveBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/></svg> Save All to Vault`;
  _bulkParsed = [];
  document.getElementById("bulk-parser-input").value = "";
  document.getElementById("bulk-parsed-preview").innerHTML = "";
  const statsBar = document.getElementById("bulk-stats-bar");
  if (statsBar) statsBar.style.display = "none";
  saveBtn.style.display = "none";
  closePowerModal("bulk-parser-modal");
  showToast(`Bulk import: ${saved} saved${failed?", "+failed+" failed":""}.`, saved>0?"success":"error");
};

function getPlatformColor(platform) {
  const colors = {
    gmail:"#ea4335", facebook:"#1877f2", instagram:"#e1306c",
    twitter:"#1da1f2", tiktok:"#ff0050", snapchat:"#fffc00",
    youtube:"#ff0000", discord:"#5865f2", telegram:"#2ca5e0",
    github:"#6e40c9", linkedin:"#0a66c2", reddit:"#ff4500",
    netflix:"#e50914", amazon:"#ff9900", apple:"#aaa", spotify:"#1db954",
    paypal:"#003087", binance:"#f3ba2f"
  };
  return colors[platform] || "#60a5fa";
}

// ── AI DIRECT ACTIONS ──
// Rich, button-driven assistant: every command can be triggered by clicking a
// chip — no typing required. Destructive commands ASK first, with a 30-second
// auto-cancel countdown. Account lists render as cards.
window._aiPendingAction    = null; // { type, ids, label, expiresAt, timerId, msgEl, scope }
window._aiPendingChallenge = null; // { code, ids, label, names, msgEl, expiresAt, timerId }

const AI_CONFIRM_RE  = /^\s*(yes|y|yep|yeah|yup|ok|okay|sure|confirm|go|do it|proceed|হ্যাঁ|হা|করো|delete|kor|koro)\s*[.!]?\s*$/i;
const AI_CANCEL_RE   = /^\s*(no|n|nope|cancel|stop|abort|না|naa|don'?t)\s*[.!]?\s*$/i;
const AI_CONFIRM_TTL = 30 * 1000;  // 30 seconds for yes/no
const AI_CHALLENGE_TTL = 60 * 1000; // 60 seconds for the security code

function _aiClearPendingTimer() {
  const p = window._aiPendingAction;
  if (p && p.timerId) { clearInterval(p.timerId); p.timerId = null; }
}
function _aiClearPending() {
  _aiClearPendingTimer();
  window._aiPendingAction = null;
}
function _aiPending() {
  const p = window._aiPendingAction;
  if (!p) return null;
  if (Date.now() > p.expiresAt) { _aiClearPending(); return null; }
  return p;
}

function _aiClearChallenge() {
  const c = window._aiPendingChallenge;
  if (c && c.timerId) { clearInterval(c.timerId); c.timerId = null; }
  window._aiPendingChallenge = null;
}
function _aiActiveChallenge() {
  const c = window._aiPendingChallenge;
  if (!c) return null;
  if (Date.now() > c.expiresAt) { _aiClearChallenge(); return null; }
  return c;
}

// Look up readable display names for the IDs about to be deleted
function _aiNamesForIds(ids) {
  const accs = window.allAccounts || [];
  return (ids || []).map(id => {
    const a = accs.find(x => x.id === id);
    if (!a) return "Unknown account";
    return a.name || a.email || a.uid || `Untitled (${id.slice(0,6)})`;
  });
}

// _aiExecutePending → does NOT delete anymore for delete_* types.
// Instead, it raises a SECOND-stage security challenge requiring the
// user to type a random 4-digit code. Only after that code matches
// is the delete actually performed.
async function _aiExecutePending(pending) {
  const ids = pending.ids || [];
  const oldMsgEl = pending.msgEl;
  const isDelete = /^delete_/.test(pending.type || "");
  _aiClearPending();
  if (oldMsgEl) _aiFinalisePending(oldMsgEl, "✅ Confirmed — security check required");
  if (!ids.length) return { text: "Nothing to delete — list was empty." };

  if (!isDelete) {
    // Fallback path for any non-delete pending types (none today, but safe)
    let ok = 0, fail = 0;
    for (const id of ids) {
      try { await remove(ref(db, `${ADMIN_COLLECTION}/${id}`)); ok++; }
      catch { fail++; }
    }
    if (ok > 0) addVaultLog("bulk_deleted", `${ok} ${pending.label}`, "other", `Deleted via AI Assistant`);
    return fail === 0
      ? { text: `🗑️ Done! Deleted ${ok} ${pending.label}.` }
      : { text: `⚠️ Deleted ${ok}, failed ${fail}.` };
  }

  // Build the challenge payload — the bubble installer will register
  // the pending challenge state via _aiInstallChallenge once rendered.
  const code  = String(1000 + Math.floor(Math.random() * 9000));
  const names = _aiNamesForIds(ids);
  return {
    challenge: {
      code,
      ids,
      label: pending.label,
      names,
      ttlMs: AI_CHALLENGE_TTL,
    }
  };
}

// Actually perform the delete after the code matches
async function _aiExecuteChallenge(challenge) {
  const ids   = challenge.ids || [];
  const msgEl = challenge.msgEl;
  _aiClearChallenge();
  if (!ids.length) return { text: "Nothing to delete — list was empty." };
  let ok = 0, fail = 0;
  for (const id of ids) {
    try { await remove(ref(db, `${ADMIN_COLLECTION}/${id}`)); ok++; }
    catch { fail++; }
  }
  if (ok > 0) addVaultLog("bulk_deleted", `${ok} ${challenge.label}`, "other", `Deleted via AI Assistant (security code verified)`);
  if (msgEl) _aiFinalisePending(msgEl, "✅ Code verified — deleted permanently");
  if (fail === 0) return { text: `🗑️ Permanently deleted ${ok} ${challenge.label} from Firebase.` };
  return { text: `⚠️ Deleted ${ok}, failed ${fail}. Check Firebase rules / network.` };
}

function _aiFinalisePending(msgEl, statusText) {
  if (!msgEl) return;
  const box = msgEl.querySelector(".ai-confirm-box");
  if (!box) return;
  box.classList.add("done");
  box.innerHTML = `<div class="ai-confirm-status">${escHtml(statusText)}</div>`;
}

const AI_CMD_DEFS = [
  { id: "summary",      icon: "📊", label: "Summary",         cmd: "show summary" },
  { id: "score",        icon: "🛡️", label: "Security score",  cmd: "security score" },
  { id: "platforms",    icon: "🧩", label: "Platform breakdown", cmd: "platform breakdown" },
  { id: "list_dead",    icon: "💀", label: "Dead accounts",   cmd: "show dead accounts" },
  { id: "list_live",    icon: "✅", label: "Live accounts",   cmd: "show live accounts" },
  { id: "weak",         icon: "⚠️", label: "Weak passwords",  cmd: "find weak passwords" },
  { id: "no_2fa",       icon: "🔒", label: "No 2FA",          cmd: "show no 2fa accounts" },
  { id: "duplicates",   icon: "♊", label: "Duplicates",       cmd: "find duplicates" },
  { id: "recent",       icon: "🕒", label: "Added this week", cmd: "show recent accounts" },
  { id: "activity",     icon: "📜", label: "Recent activity", cmd: "show recent activity" },
  { id: "status",       icon: "🩺", label: "System status",   cmd: "system status" },
  { id: "search",       icon: "🔎", label: "Search…",         cmd: "search " },
  { id: "delete_dead",  icon: "🗑️", label: "Delete dead",     cmd: "delete all dead accounts", style: "danger" },
  { id: "analytics",    icon: "📈", label: "Open analytics",  cmd: "show analytics" },
  { id: "export",       icon: "📥", label: "Export",          cmd: "export accounts" },
];

// ── Computed insights used by several AI replies ──
function _aiSecurityScore() {
  const accs = (window.allAccounts || []).slice();
  const total = accs.length;
  if (!total) {
    return { total: 0, score: 100, grade: "A+", color: "green",
             weak: 0, noTfa: 0, dead: 0, missingEmail: 0, missingPwd: 0 };
  }
  const weak         = accs.filter(a => a.password && isWeakPassword(a.password)).length;
  const noTfa        = accs.filter(a => !a.twoFaKey || !a.twoFaKey.trim()).length;
  const dead         = accs.filter(a => a.status === "dead").length;
  const missingEmail = accs.filter(a => !a.email || !a.email.trim()).length;
  const missingPwd   = accs.filter(a => !a.password || !a.password.trim()).length;
  // Penalties (per account share, weighted).
  const pen = (
    (weak         / total) * 35 +
    (noTfa        / total) * 25 +
    (dead         / total) * 15 +
    (missingPwd   / total) * 15 +
    (missingEmail / total) * 10
  );
  const score = Math.max(0, Math.min(100, Math.round(100 - pen)));
  let grade, color;
  if (score >= 95)      { grade = "A+"; color = "green"; }
  else if (score >= 85) { grade = "A";  color = "green"; }
  else if (score >= 75) { grade = "B";  color = "blue";  }
  else if (score >= 60) { grade = "C";  color = "yellow";}
  else if (score >= 40) { grade = "D";  color = "yellow";}
  else                  { grade = "F";  color = "red";   }
  return { total, score, grade, color, weak, noTfa, dead, missingEmail, missingPwd };
}

function _aiFindDuplicates() {
  const accs = (window.allAccounts || []).slice();
  const byEmail = new Map();
  const byPwd   = new Map();
  for (const a of accs) {
    const e = (a.email || "").trim().toLowerCase();
    const p = (a.password || "").trim();
    if (e) {
      if (!byEmail.has(e)) byEmail.set(e, []);
      byEmail.get(e).push(a);
    }
    if (p) {
      if (!byPwd.has(p)) byPwd.set(p, []);
      byPwd.get(p).push(a);
    }
  }
  const dupEmails = [...byEmail.values()].filter(g => g.length > 1);
  const dupPwds   = [...byPwd.values()].filter(g => g.length > 1);
  return { dupEmails, dupPwds };
}

// Async helper: tries backend first, falls back to local sync compute.
// Returns the same shape `_aiSecurityScore()` produces, plus duplicates/platforms.
async function _aiBackendAnalyze() {
  try {
    if (window.apiClient) {
      const r = await window.apiClient.analyze(window.allAccounts || []);
      if (r && r.ok && r.data && r.data.ok) {
        const d = r.data;
        // map backend grades A-F to UI colors
        const colorFor = g => g === 'A' ? 'green'
                            : g === 'B' ? 'green'
                            : g === 'C' ? 'blue'
                            : g === 'D' ? 'yellow'
                            : g === 'E' ? 'yellow' : 'red';
        return {
          source: 'backend',
          total: d.total, score: d.score, grade: d.grade, color: colorFor(d.grade),
          weak: d.weak, noTfa: d.noTfa, dead: d.dead,
          missingEmail: 0, missingPwd: 0,
          duplicates: d.duplicates || { emails: [], passwords: [] },
          platforms: d.platforms || [],
        };
      }
    }
  } catch (_) {}
  // ── fallback to local compute ──
  const s = _aiSecurityScore();
  const { dupEmails, dupPwds } = _aiFindDuplicates();
  const platforms = _aiPlatformBreakdown().map(p => ({ name: p.platform, count: p.count }));
  return {
    source: 'local',
    ...s,
    duplicates: {
      emails: dupEmails.map(g => ({ email: (g[0] && g[0].email) || '', count: g.length, platforms: g.map(a => a.platform || '') })),
      passwords: dupPwds.map(g => ({ count: g.length, accounts: g.map(a => a.uid || a.email || a.platform) })),
    },
    platforms,
  };
}

function _aiPlatformBreakdown() {
  const accs = (window.allAccounts || []).slice();
  const map = new Map();
  for (const a of accs) {
    const k = a.platform || "other";
    map.set(k, (map.get(k) || 0) + 1);
  }
  const list = [...map.entries()]
    .map(([platform, count]) => ({
      platform, count,
      label: getPlatformLabel(platform),
      color: getPlatformColor(platform),
    }))
    .sort((a, b) => b.count - a.count);
  return list;
}

function _aiAccountTime(a) {
  // Best-effort timestamp for "added at" — falls back to 0 if unknown.
  return a.createdAt || a.created_at || a.addedAt || a.added_at || a.timestamp || a.ts || 0;
}

function _aiAcctsToCards(list, max = 8) {
  return list.slice(0, max).map(a => ({
    id: a.id,
    name: a.name || a.email || a.uid || "Unnamed",
    sub: [a.email, a.uid].filter(Boolean).join(" · ") || (a.platform ? "" : ""),
    platform: a.platform || "other",
    platformLabel: getPlatformLabel(a.platform || "other"),
    status: a.status || "unknown",
    twoFa: !!a.twoFaKey,
    weak: isWeakPassword(a.password),
  }));
}

async function processAIDirectAction(text) {
  const t = text.toLowerCase().trim();
  const tRaw = text.trim();

  // ── 0) Active SECURITY CHALLENGE has highest priority ──
  // (User has clicked Yes on a destructive action and now must type the code.)
  const challenge = _aiActiveChallenge();
  if (challenge) {
    if (tRaw === challenge.code) return await _aiExecuteChallenge(challenge);
    if (AI_CANCEL_RE.test(t)) {
      const msgEl = challenge.msgEl;
      _aiClearChallenge();
      if (msgEl) _aiFinalisePending(msgEl, "❎ Cancelled — nothing deleted");
      return { text: "❎ Cancelled. Nothing was deleted." };
    }
    // Wrong/other input → reject but keep challenge active until timeout
    return {
      text: `🚫 Code mismatch. Type **${challenge.code}** exactly to confirm deletion, or type **cancel** to abort.`
    };
  }

  // ── 1) Pending-confirmation handling FIRST (so yes/no land here) ──
  const pending = _aiPending();
  if (pending) {
    if (AI_CONFIRM_RE.test(t)) return await _aiExecutePending(pending);
    if (AI_CANCEL_RE.test(t))  {
      const msgEl = pending.msgEl;
      _aiClearPending();
      if (msgEl) _aiFinalisePending(msgEl, "❎ Cancelled");
      return { text: "❎ Cancelled. Nothing was deleted." };
    }
    // Anything else cancels the pending action so users aren't trapped.
    const msgEl = pending.msgEl;
    _aiClearPending();
    if (msgEl) _aiFinalisePending(msgEl, "❎ Cancelled (new command)");
  }

  // ── 2) Destructive commands → ASK FIRST ──

  // Delete ALL accounts (most destructive)
  if (/delete|remove|wipe|clear/.test(t) && /all/.test(t) && /account/.test(t) && !/dead|live|weak|2fa/.test(t)) {
    if (!allAccounts.length) return { text: "There are no accounts to delete." };
    return _aiBuildConfirm({
      type: "delete_all",
      ids: allAccounts.map(a => a.id),
      label: `account(s)`,
      title: `⚠️ This will delete ALL ${allAccounts.length} account(s) from Firebase.`,
      accounts: _aiAcctsToCards(allAccounts, 6),
      moreCount: Math.max(0, allAccounts.length - 6),
    });
  }

  // Delete DEAD accounts
  if (/delete|remove|wipe|clear/.test(t) && /dead/.test(t) && !/don't|dont/.test(t)) {
    const deadAccs = allAccounts.filter(a => a.status === "dead");
    if (!deadAccs.length) return { text: "✅ No dead accounts found to delete." };
    return _aiBuildConfirm({
      type: "delete_dead",
      ids: deadAccs.map(a => a.id),
      label: `dead account(s)`,
      title: `💀 Found ${deadAccs.length} dead account${deadAccs.length>1?"s":""}. Delete all?`,
      accounts: _aiAcctsToCards(deadAccs, 8),
      moreCount: Math.max(0, deadAccs.length - 8),
    });
  }

  // Delete accounts with NO 2FA
  if (/delete|remove/.test(t) && /(no.?2fa|without.?2fa|no.?two.?factor)/.test(t)) {
    const noTFA = allAccounts.filter(a => !a.twoFaKey);
    if (!noTFA.length) return { text: "✅ Every account has 2FA — nothing to delete." };
    return _aiBuildConfirm({
      type: "delete_no_2fa",
      ids: noTFA.map(a => a.id),
      label: `no-2FA account(s)`,
      title: `🔒 Delete ${noTFA.length} account${noTFA.length>1?"s":""} without 2FA?`,
      accounts: _aiAcctsToCards(noTFA, 8),
      moreCount: Math.max(0, noTFA.length - 8),
    });
  }

  // Delete accounts with WEAK passwords
  if (/delete|remove/.test(t) && /weak/.test(t) && /password/.test(t)) {
    const weak = allAccounts.filter(a => isWeakPassword(a.password));
    if (!weak.length) return { text: "✅ No weak-password accounts to delete." };
    return _aiBuildConfirm({
      type: "delete_weak",
      ids: weak.map(a => a.id),
      label: `weak-password account(s)`,
      title: `⚠️ Delete ${weak.length} weak-password account${weak.length>1?"s":""}?`,
      accounts: _aiAcctsToCards(weak, 8),
      moreCount: Math.max(0, weak.length - 8),
    });
  }

  // ── 3) Read-only commands ──

  // Summary / counts
  if (/how many|count|total|summary|stat/.test(t) && /account/.test(t) || t === "show summary") {
    const live = allAccounts.filter(a => a.status === "live").length;
    const dead = allAccounts.filter(a => a.status === "dead").length;
    const noTFA = allAccounts.filter(a => !a.twoFaKey).length;
    const weak = allAccounts.filter(a => isWeakPassword(a.password)).length;
    return {
      text: `📊 Account Summary`,
      stats: [
        { label: "Total", value: allAccounts.length, color: "blue" },
        { label: "Live", value: live, color: "green" },
        { label: "Dead", value: dead, color: "red" },
        { label: "No 2FA", value: noTFA, color: "yellow" },
        { label: "Weak passwords", value: weak, color: "red" },
      ],
      actions: [
        { label: "Open analytics", cmd: "show analytics", icon: "📈" },
        ...(dead > 0 ? [{ label: `Delete ${dead} dead`, cmd: "delete all dead accounts", icon: "🗑️", style: "danger" }] : []),
      ],
    };
  }

  // Show live accounts
  if (/show|list|find/.test(t) && /live/.test(t)) {
    const liveAccs = allAccounts.filter(a => a.status === "live");
    if (!liveAccs.length) return { text: "No live accounts found." };
    return {
      text: `✅ Live accounts (${liveAccs.length})`,
      accounts: _aiAcctsToCards(liveAccs, 10),
      moreCount: Math.max(0, liveAccs.length - 10),
    };
  }

  // Show dead accounts
  if (/show|list|find/.test(t) && /dead/.test(t)) {
    const deadAccs = allAccounts.filter(a => a.status === "dead");
    if (!deadAccs.length) return { text: "No dead accounts found." };
    return {
      text: `💀 Dead accounts (${deadAccs.length})`,
      accounts: _aiAcctsToCards(deadAccs, 10),
      moreCount: Math.max(0, deadAccs.length - 10),
      actions: [
        { label: `Delete all ${deadAccs.length} dead`, cmd: "delete all dead accounts", icon: "🗑️", style: "danger" },
      ],
    };
  }

  // Weak password scan
  if (/weak/.test(t) && /password/.test(t) || /security.?scan/.test(t) || /security.?audit/.test(t)) {
    const weak = allAccounts.filter(a => isWeakPassword(a.password));
    if (!weak.length) return { text: "✅ No weak passwords detected! All accounts have strong passwords." };
    return {
      text: `⚠️ Found ${weak.length} account${weak.length>1?"s":""} with weak passwords`,
      accounts: _aiAcctsToCards(weak, 8),
      moreCount: Math.max(0, weak.length - 8),
      hint: "Use 12+ characters mixing upper, lower, numbers, and symbols.",
      actions: [
        { label: `Delete these ${weak.length}`, cmd: "delete weak password accounts", icon: "🗑️", style: "danger" },
      ],
    };
  }

  // No 2FA scan
  if (/2fa|two.?factor|no.*fa/.test(t)) {
    const noTFA = allAccounts.filter(a => !a.twoFaKey);
    if (!noTFA.length) return { text: "✅ All accounts have 2FA enabled!" };
    return {
      text: `🔒 ${noTFA.length} account${noTFA.length>1?"s":""} without 2FA`,
      accounts: _aiAcctsToCards(noTFA, 8),
      moreCount: Math.max(0, noTFA.length - 8),
      hint: "Add TOTP keys in the account edit modal for these accounts.",
      actions: [
        { label: `Delete these ${noTFA.length}`, cmd: "delete no 2fa accounts", icon: "🗑️", style: "danger" },
      ],
    };
  }

  // Open analytics
  if (/analytic|report|chart|statistic/.test(t)) {
    setTimeout(() => openAnalytics(), 300);
    return { text: "📊 Opening Analytics report for you..." };
  }

  // Export
  if (/export|download/.test(t)) {
    setTimeout(() => window.downloadAccountsTxt && window.downloadAccountsTxt(), 300);
    return { text: "📥 Preparing account export..." };
  }

  // Greeting / hi / hello (time aware)
  if (/^\s*(hi|hello|hey|yo|salam|assalam|namaste|হ্যালো|হাই|হেলো)\s*[.!?]?\s*$/i.test(t)) {
    const h = new Date().getHours();
    const part = h < 5 ? "Good night" : h < 12 ? "Good morning" : h < 17 ? "Good afternoon" : h < 21 ? "Good evening" : "Good night";
    const total = (window.allAccounts || []).length;
    return {
      text: `${part}! 👋  You have **${total} account${total === 1 ? "" : "s"}** in the vault. What would you like to do?`,
      actions: [
        { label: "Security score", cmd: "security score", icon: "🛡️" },
        { label: "Summary",        cmd: "show summary",   icon: "📊" },
        { label: "Help",           cmd: "help",           icon: "💡" },
      ],
    };
  }

  // Clear chat
  if (/^\s*(clear|reset|wipe|erase)( chat| screen| history)?\s*[.!?]?\s*$/i.test(t)) {
    const c = document.getElementById("ai-modal-messages");
    if (c) c.innerHTML = "";
    return { text: "🧹 Chat cleared. How can I help?" };
  }

  // ── Security score / vault audit ──
  if (/security.?score|vault.?score|score|grade|how.?safe|how.?secure|audit/.test(t)) {
    const s = await _aiBackendAnalyze();
    if (!s.total) return { text: "Add some accounts first — there's nothing to score yet." };
    const verdict = s.score >= 90 ? "Excellent — vault is very well secured."
                   : s.score >= 75 ? "Good — a few small things to tighten."
                   : s.score >= 60 ? "Fair — several issues worth fixing."
                   : s.score >= 40 ? "Risky — please act on the items below."
                                   : "Critical — the vault has serious gaps.";
    return {
      text: `🛡️ **Vault Security Score**\n${verdict}`,
      scoreGauge: s,
      actions: [
        ...(s.weak  > 0 ? [{ label: `${s.weak} weak`,    cmd: "find weak passwords",  icon: "⚠️" }] : []),
        ...(s.noTfa > 0 ? [{ label: `${s.noTfa} no 2FA`, cmd: "show no 2fa accounts", icon: "🔒" }] : []),
        ...(s.dead  > 0 ? [{ label: `${s.dead} dead`,    cmd: "show dead accounts",   icon: "💀" }] : []),
        { label: "Open analytics", cmd: "show analytics", icon: "📈" },
      ],
    };
  }

  // ── System status (backend + firebase + errors) ──
  if (/^\s*(system.?status|status|sysh|health|ping)\s*[.!?]?\s*$/i.test(t)) {
    const wb = (window.VaultBackend && window.VaultBackend.status) || {};
    const errs = (window.VaultDebug && VaultDebug._getErrors)
                 ? VaultDebug._getErrors() : [];
    const errCount  = errs.filter(e => e.level === "error").length;
    const warnCount = errs.filter(e => e.level === "warn").length;
    const fb = (typeof _fbSubBound !== "undefined") ? null : null; // best-effort
    return {
      text: "🩺 **System Status**",
      statusPills: [
        { label: "Backend", value: wb.online ? `${wb.latencyMs || 0}ms` : "offline", ok: !!wb.online },
        { label: "Errors",  value: String(errCount),  ok: errCount === 0, warn: errCount === 0 && warnCount > 0 },
        { label: "Warnings",value: String(warnCount), ok: warnCount === 0, warn: warnCount > 0 },
        { label: "Online",  value: navigator.onLine ? "yes" : "no", ok: navigator.onLine },
        { label: "Secure",  value: window.isSecureContext ? "HTTPS" : "no", ok: window.isSecureContext },
      ],
      actions: [
        { label: "Open System Health", cmd: "open system health", icon: "🩺" },
        { label: "Open Realtime Log",  cmd: "open realtime log",  icon: "📡" },
      ],
    };
  }

  // Open system health / realtime log shortcuts
  if (/open.?(system.?)?health/.test(t)) {
    setTimeout(() => window.openSystemHealth && window.openSystemHealth(), 250);
    return { text: "🩺 Opening System Health…" };
  }
  if (/open.?(realtime|live).?log/.test(t)) {
    setTimeout(() => window.openRealtimeLog && window.openRealtimeLog(), 250);
    return { text: "📡 Opening Realtime Log…" };
  }

  // ── Platform breakdown ──
  if (/(platform|provider).?(breakdown|distribution|chart|by)/.test(t)
      || /^\s*by platform\s*$/i.test(t)
      || /accounts.?by.?platform/.test(t)) {
    // Use local enriched version (with label/color) but rely on backend for counts when possible.
    const ana = await _aiBackendAnalyze();
    const list = _aiPlatformBreakdown(); // local — has UI labels/colors
    if (!list.length) return { text: "No platforms to break down — vault is empty." };
    return {
      text: `🧩 **Accounts by platform** (${list.length} platform${list.length>1?"s":""})`,
      bars: list,
      barsTotal: list.reduce((a,b)=>a+b.count,0),
      sourceTag: ana.source === 'backend' ? '🛰️ backend' : '💻 local',
    };
  }

  // ── Duplicates (email + password) ──
  if (/duplicate|dup|duplicates|reused|repeated/.test(t)) {
    await _aiBackendAnalyze(); // warm backend (and validate)
    const { dupEmails, dupPwds } = _aiFindDuplicates();
    if (!dupEmails.length && !dupPwds.length) {
      return { text: "✅ No duplicate emails or passwords found — every account is unique." };
    }
    const flat = [];
    dupPwds.forEach(g => g.forEach(a => flat.push(a)));
    const cards = _aiAcctsToCards(flat, 10);
    const lines = [];
    if (dupPwds.length)   lines.push(`🔁 **${dupPwds.length}** password(s) reused across ${dupPwds.reduce((a,g)=>a+g.length,0)} accounts`);
    if (dupEmails.length) lines.push(`📧 **${dupEmails.length}** email(s) appear on multiple accounts`);
    return {
      text: lines.join("\n"),
      accounts: cards,
      moreCount: Math.max(0, flat.length - cards.length),
      hint: "Tip: every account should have its own unique password — reuse is the #1 attack vector.",
    };
  }

  // ── Recently added (last 7 days) ──
  if (/(recent|new|latest|added).?(account|this.?week|today)/.test(t)
      || /^\s*(recent|latest)\s*$/i.test(t)) {
    const now = Date.now();
    const weekAgo = now - 7 * 24 * 3600 * 1000;
    const recent = (window.allAccounts || [])
      .map(a => ({ a, t: _aiAccountTime(a) }))
      .filter(x => x.t && x.t >= weekAgo)
      .sort((x,y) => y.t - x.t)
      .map(x => x.a);
    if (!recent.length) return { text: "No accounts have been added in the last 7 days." };
    return {
      text: `🕒 **${recent.length} account${recent.length>1?"s":""}** added in the last 7 days`,
      accounts: _aiAcctsToCards(recent, 10),
      moreCount: Math.max(0, recent.length - 10),
    };
  }

  // ── Recent vault activity (read from vault_logs in memory if any) ──
  if (/recent.?(activity|log|action|history)/.test(t) || /^\s*activity\s*$/i.test(t)) {
    const logs = (window._recentVaultLogs && window._recentVaultLogs.slice()) || [];
    if (!logs.length) {
      return {
        text: "No recent vault activity to show yet. Activity is recorded as you add, edit, or delete accounts.",
        actions: [{ label: "Show summary", cmd: "show summary", icon: "📊" }],
      };
    }
    const items = logs.slice(-10).reverse();
    return {
      text: `📜 **Recent activity** · last ${items.length} event${items.length>1?"s":""}`,
      timeline: items,
    };
  }

  // ── Search (search foo / find foo) ──
  const searchM = t.match(/^\s*(?:search|find|look\s*for|lookup)\s+(.+?)\s*$/i);
  if (searchM && !/weak|2fa|dead|live|duplicate/.test(searchM[1])) {
    const q = searchM[1].toLowerCase().trim();
    if (q.length < 2) return { text: "Please give me at least 2 characters to search for." };
    const hits = (window.allAccounts || []).filter(a => {
      return [a.name, a.email, a.uid, a.number, a.platform].some(v =>
        String(v || "").toLowerCase().includes(q)
      );
    });
    if (!hits.length) return { text: `🔎 No matches for **${searchM[1]}**` };
    return {
      text: `🔎 Found **${hits.length}** match${hits.length>1?"es":""} for "${searchM[1]}"`,
      accounts: _aiAcctsToCards(hits, 10),
      moreCount: Math.max(0, hits.length - 10),
    };
  }

  // ── Missing fields (email / phone / password / 2fa) ──
  if (/missing|without|no\s+(email|phone|number|password|pwd|pic|photo|image|2fa|two.?factor)/.test(t)
      || /^show\s+(no|missing)/.test(t)) {
    const accs = window.allAccounts || [];
    let group = "field", filtered = [];
    if (/email/.test(t))                     { group = "email";    filtered = accs.filter(a => !a.email   || !a.email.trim());   }
    else if (/phone|number/.test(t))         { group = "phone";    filtered = accs.filter(a => !a.number  || !a.number.trim());  }
    else if (/password|pwd/.test(t))         { group = "password"; filtered = accs.filter(a => !a.password|| !a.password.trim());}
    else if (/pic|photo|image|avatar/.test(t)){ group = "photo";   filtered = accs.filter(a => !a.imageUrl|| !a.imageUrl.trim());}
    else if (/2fa|two.?factor/.test(t))      { group = "2FA";      filtered = accs.filter(a => !a.twoFaKey||!a.twoFaKey.trim());}
    if (filtered.length === 0)
      return { text: `✅ Every account has a ${group} on file.` };
    return {
      text: `📭 **${filtered.length} account${filtered.length>1?"s":""}** missing ${group}`,
      accounts: _aiAcctsToCards(filtered, 10),
      moreCount: Math.max(0, filtered.length - 10),
    };
  }

  // ── Recheck shortcut ──
  if (/^\s*(recheck|rescan|refresh|verify)\s*(all)?\s*(accounts?)?\s*[.!?]?\s*$/i.test(t)) {
    if (typeof window.recheckAllAccounts === "function") {
      setTimeout(() => window.recheckAllAccounts({}), 300);
      return { text: "🔄 Starting full recheck of all accounts…" };
    }
  }

  // Help / menu
  if (/^\s*(help|menu|commands?|options?|what.?can.?you.?do)\s*[.!?]?\s*$/i.test(t)) {
    return {
      text: "Here are the things I can do — tap any chip:",
      actions: AI_CMD_DEFS.map(d => ({ label: d.label, cmd: d.cmd, icon: d.icon, style: d.style })),
    };
  }

  return null; // Not a direct action, use AI API
}

function _aiBuildConfirm(opts) {
  // Returns a payload describing the confirm UI. The actual pending state is
  // installed by _aiInstallPending once the message bubble is rendered.
  return {
    text: opts.title,
    accounts: opts.accounts,
    moreCount: opts.moreCount || 0,
    confirm: {
      type: opts.type,
      ids: opts.ids,
      label: opts.label,
      ttlMs: AI_CONFIRM_TTL,
    },
  };
}

// ── HEALTH NOTE GENERATION (separate from custom note) ──
function generateHealthNote(data) {
  const issues = [];
  if (!data.imageUrl || !data.imageUrl.trim()) issues.push("📷 No profile photo");
  if (!data.email || !data.email.trim()) issues.push("📧 No email linked");
  if (!data.number || !data.number.trim()) issues.push("📱 No phone number");
  if (!data.twoFaKey || !data.twoFaKey.trim()) issues.push("🔐 No 2FA set");
  if (!data.password || !data.password.trim()) issues.push("🔑 No password saved");
  else if (isWeakPassword(data.password)) issues.push("⚠️ Weak password");
  return issues.join(" · ");
}

// ── LEGACY: kept for compatibility ──
async function generateAutoNote(data, existingNote) {
  return existingNote;

  const issues = [];
  if (!data.twoFaKey) issues.push("⚠️ No 2FA key configured — add TOTP for better security");
  if (isWeakPassword(data.password)) issues.push("⚠️ Weak password detected — use a stronger password (12+ chars, mixed case)");
  if (issues.length === 0) return existingNote;

  const autoNote = issues.join("\n");
  if (!existingNote) return autoNote;
  if (existingNote.includes("⚠️ No 2FA") || existingNote.includes("⚠️ Weak")) {
    // Replace old auto notes
    const cleaned = existingNote.replace(/⚠️ No 2FA[^\n]*/g,"").replace(/⚠️ Weak[^\n]*/g,"").trim();
    return cleaned ? cleaned + "\n" + autoNote : autoNote;
  }
  return existingNote + "\n" + autoNote;
}

// ══════════════════════════════════════════════════════
// REALTIME LOG SYSTEM — continuous monitoring console
// ══════════════════════════════════════════════════════
const RealtimeLogger = (() => {
  const MAX_BUFFER = 400;
  const buffer = [];
  const subscribers = new Set();
  let intervalId = null;
  let isRunning = false;
  let stats = { total: 0, ok: 0, info: 0, warn: 0, error: 0, byKind: {} };
  let _consoleHooked = false;
  let _netHooked = false;

  function fmtTime(t) {
    const d = new Date(t);
    const pad = n => String(n).padStart(2, "0");
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3,"0")}`;
  }

  function push(level, kind, message, meta) {
    const entry = {
      id: Date.now() + "_" + Math.random().toString(36).slice(2, 7),
      ts: Date.now(),
      level: level || "info",     // ok | info | warn | error
      kind:  kind  || "system",   // backend | firebase | api | recheck | security | system | js
      message: String(message || ""),
      meta: meta || null
    };
    buffer.push(entry);
    if (buffer.length > MAX_BUFFER) buffer.shift();
    stats.total++;
    stats[entry.level] = (stats[entry.level] || 0) + 1;
    stats.byKind[entry.kind] = (stats.byKind[entry.kind] || 0) + 1;
    subscribers.forEach(fn => { try { fn(entry); } catch (_) {} });
    return entry;
  }

  function subscribe(fn) {
    subscribers.add(fn);
    return () => subscribers.delete(fn);
  }

  function getAll()   { return buffer.slice(); }
  function getStats() { return JSON.parse(JSON.stringify(stats)); }

  function clear() {
    buffer.length = 0;
    stats = { total: 0, ok: 0, info: 0, warn: 0, error: 0, byKind: {} };
    subscribers.forEach(fn => { try { fn(null, true); } catch (_) {} });
  }

  // ─── Periodic checks ───────────────────────────────
  // _fbConnected stays `null` until Firebase fires the FIRST real
  // `.info/connected` event — we never log a "disconnected" until we
  // have actually observed a connected→disconnected transition. This
  // kills the false "RTDB disconnected" noise on cold start.
  let _backendOk = null, _fbConnected = null, _lastErrCount = 0, _lastWarnCount = 0;
  let _fbSubBound = false;
  let _lastConfigOk = null;
  let _authObserved = null; // true once we've seen a signed-in user at least once
  let _lastSecSig = "";     // signature for security state — only push on change

  async function checkBackend() {
    const t0 = performance.now();
    try {
      const res = await fetch("/api/health", { cache: "no-store" });
      const ms = Math.round(performance.now() - t0);
      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        if (_backendOk !== true) {
          push("ok", "backend", `Backend healthy (${ms}ms)`, data);
          _backendOk = true;
        }
      } else {
        push("error", "backend", `Backend returned HTTP ${res.status} (${ms}ms)`);
        _backendOk = false;
      }
    } catch (e) {
      const ms = Math.round(performance.now() - t0);
      push("error", "backend", `Backend unreachable: ${e.message} (${ms}ms)`);
      _backendOk = false;
    }
  }

  async function checkConfig() {
    try {
      const res = await fetch("/api/config", { cache: "no-store" });
      if (!res.ok) {
        if (_lastConfigOk !== false)
          push("error", "api", `/api/config HTTP ${res.status}`);
        _lastConfigOk = false;
        return;
      }
      const data = await res.json().catch(() => null);
      if (!data || !data.ok || !data.cfg || !data.cfg.databaseURL) {
        if (_lastConfigOk !== false)
          push("warn", "api", `/api/config returned malformed payload`);
        _lastConfigOk = false;
      } else if (_lastConfigOk !== true) {
        push("ok", "api", `/api/config OK`);
        _lastConfigOk = true;
      }
    } catch (e) {
      if (_lastConfigOk !== false)
        push("error", "api", `/api/config error: ${e.message}`);
      _lastConfigOk = false;
    }
  }

  // Bind .info/connected ONCE, persistently. Only push on real
  // state transitions — never on the initial uncertain snapshot.
  function bindFirebaseListener() {
    if (_fbSubBound) return;
    try {
      if (typeof db === "undefined" || !db || typeof ref !== "function") return;
      const cRef = ref(db, ".info/connected");
      _fbSubBound = true;
      onValue(cRef, snap => {
        const v = !!snap.val();
        // First event is the "current" state — no transition has happened
        // yet, so we just record it without logging. This is what kills
        // the false "RTDB disconnected" message on cold-start.
        if (_fbConnected === null) {
          _fbConnected = v;
          if (v) push("ok", "firebase", "Firebase RTDB connected");
          return;
        }
        if (v !== _fbConnected) {
          push(v ? "ok" : "error", "firebase",
               v ? "Firebase RTDB reconnected" : "Firebase RTDB disconnected");
          _fbConnected = v;
        }
      });
    } catch (e) {
      push("error", "firebase", `Firebase listener error: ${e.message}`);
    }
  }

  function checkAuth() {
    try {
      const u = auth && auth.currentUser;
      const isIn = !!u;
      // Only log on transitions — and never log "no user" before we've
      // ever seen one (that's the normal pre-login state, not an error).
      if (_authObserved === null) {
        _authObserved = isIn;
        if (isIn) push("ok", "security", `Signed in as ${u.email || u.uid}`);
        return;
      }
      if (isIn !== _authObserved) {
        push(isIn ? "ok" : "warn", "security",
             isIn ? `Signed in as ${u.email || u.uid}` : "User signed out");
        _authObserved = isIn;
      }
    } catch (e) {
      push("error", "security", `Auth check error: ${e.message}`);
    }
  }

  function checkSecurity() {
    try {
      const accounts = (typeof allAccounts !== "undefined" && allAccounts) ? allAccounts : [];
      if (!accounts.length) { _lastSecSig = ""; return; }
      const noTfa  = accounts.filter(a => !a.twoFaKey || !a.twoFaKey.trim()).length;
      const weak   = accounts.filter(a => a.password && isWeakPassword(a.password)).length;
      const dead   = accounts.filter(a => a.status === "dead").length;
      // Build a signature so we ONLY emit security log lines when the
      // numbers actually change. Avoids the "every 32 sec, same warning"
      // spam that made the log feel fake.
      const sig = `${accounts.length}|${noTfa}|${weak}|${dead}`;
      if (sig === _lastSecSig) return;
      _lastSecSig = sig;
      if (weak > 0) push("warn", "security", `${weak} weak password(s) detected`);
      if (noTfa > Math.floor(accounts.length / 2))
        push("warn", "security", `${noTfa}/${accounts.length} accounts without 2FA`);
      if (dead > 0) push("warn", "security", `${dead} dead account(s) on file`);
      if (weak === 0 && dead === 0 && noTfa <= Math.floor(accounts.length / 2))
        push("ok", "security", `Vault clean · ${accounts.length} account(s)`);
    } catch (_) {}
  }

  function pollErrorBucket() {
    try {
      const errs = VaultDebug._getErrors ? VaultDebug._getErrors() : [];
      const e = errs.filter(x => x.level === "error").length;
      const w = errs.filter(x => x.level === "warn").length;
      if (e > _lastErrCount) {
        const newOnes = errs.filter(x => x.level === "error").slice(_lastErrCount);
        newOnes.forEach(x => push("error", "js", x.msg));
        _lastErrCount = e;
      }
      if (w > _lastWarnCount) {
        const newOnes = errs.filter(x => x.level === "warn").slice(_lastWarnCount);
        newOnes.forEach(x => push("warn", "js", x.msg));
        _lastWarnCount = w;
      }
    } catch (_) {}
  }

  let _tick = 0;
  async function tick() {
    _tick++;
    pollErrorBucket();
    // Bind .info/connected once Firebase is available — re-tries each
    // tick until the SDK is ready, then becomes a no-op.
    bindFirebaseListener();
    // Stagger heavy checks
    if (_tick % 1 === 0) await checkBackend();
    if (_tick % 2 === 0) await checkConfig();
    if (_tick % 3 === 0) checkAuth();
    if (_tick % 4 === 0) checkSecurity();
  }

  // ─── REAL console capture ──────────────────────────
  // Hijacks console.log/info/warn/error/debug so every log
  // emitted by the app (and any 3rd-party SDK) appears in
  // the realtime panel WITHOUT losing the original DevTools
  // output. Done once, idempotent.
  function hookConsole() {
    if (_consoleHooked || typeof console === "undefined") return;
    _consoleHooked = true;
    const map = {
      log:   { level: "info",  kind: "console" },
      info:  { level: "info",  kind: "console" },
      debug: { level: "info",  kind: "console" },
      warn:  { level: "warn",  kind: "console" },
      error: { level: "error", kind: "console" }
    };
    Object.keys(map).forEach(name => {
      const orig = console[name] ? console[name].bind(console) : (function(){});
      console[name] = function(...args) {
        try {
          const msg = args.map(a => {
            if (a == null) return String(a);
            if (typeof a === "string") return a;
            if (a instanceof Error) return a.stack || a.message;
            try { return JSON.stringify(a, (_k, v) => typeof v === "bigint" ? v.toString() : v); }
            catch { return String(a); }
          }).join(" ");
          // Skip our own internal pushes to avoid feedback loops
          if (!msg.startsWith("[RTL]")) push(map[name].level, map[name].kind, msg);
        } catch (_) {}
        orig(...args);
      };
    });
    // Global JS errors & promise rejections
    window.addEventListener("error", (ev) => {
      try {
        const m = ev.error && ev.error.stack ? ev.error.stack : (ev.message || "Unknown error");
        push("error", "js", `${m}${ev.filename ? ` @ ${ev.filename}:${ev.lineno}:${ev.colno}` : ""}`);
      } catch (_) {}
    });
    window.addEventListener("unhandledrejection", (ev) => {
      try {
        const r = ev.reason;
        const m = r && r.stack ? r.stack : (r && r.message ? r.message : String(r));
        push("error", "js", `Unhandled rejection: ${m}`);
      } catch (_) {}
    });
  }

  // ─── Network capture (fetch + XHR) ─────────────────
  // Logs every HTTP request the app makes. Filters out the
  // logger's OWN /api/health & /api/config probes (kind:backend
  // / api already covers those) so the panel stays signal-rich.
  function hookNetwork() {
    if (_netHooked || typeof window === "undefined") return;
    _netHooked = true;
    // fetch()
    if (typeof window.fetch === "function") {
      const _origFetch = window.fetch.bind(window);
      window.fetch = async function(input, init) {
        const url = typeof input === "string" ? input : (input && input.url) || "";
        const method = (init && init.method) || (input && input.method) || "GET";
        const isProbe = /\/api\/(health|config|watchdog)/.test(url);
        const t0 = performance.now();
        try {
          const res = await _origFetch(input, init);
          const ms = Math.round(performance.now() - t0);
          if (!isProbe) {
            const lvl = res.ok ? "ok" : (res.status >= 500 ? "error" : "warn");
            push(lvl, "network", `${method} ${shortUrl(url)} → ${res.status} (${ms}ms)`);
          }
          return res;
        } catch (e) {
          const ms = Math.round(performance.now() - t0);
          if (!isProbe) push("error", "network", `${method} ${shortUrl(url)} ✗ ${e.message} (${ms}ms)`);
          throw e;
        }
      };
    }
    // XHR
    if (typeof window.XMLHttpRequest === "function") {
      const XHR = window.XMLHttpRequest.prototype;
      const _open = XHR.open;
      const _send = XHR.send;
      XHR.open = function(method, url) {
        this.__rtl = { method, url, t0: 0 };
        return _open.apply(this, arguments);
      };
      XHR.send = function() {
        const meta = this.__rtl || {};
        meta.t0 = performance.now();
        const isProbe = /\/api\/(health|config|watchdog)/.test(meta.url || "");
        this.addEventListener("loadend", () => {
          if (isProbe) return;
          const ms = Math.round(performance.now() - meta.t0);
          const status = this.status || 0;
          const lvl = status === 0 ? "error" : (status >= 200 && status < 400 ? "ok" : (status >= 500 ? "error" : "warn"));
          push(lvl, "network", `${meta.method || "GET"} ${shortUrl(meta.url || "")} → ${status || "ERR"} (${ms}ms)`);
        });
        return _send.apply(this, arguments);
      };
    }
  }

  function shortUrl(u) {
    try {
      if (!u) return "";
      // Strip origin if same-origin
      if (u.startsWith(location.origin)) u = u.slice(location.origin.length);
      // Trim long query strings
      if (u.length > 80) u = u.slice(0, 77) + "…";
      return u;
    } catch { return String(u); }
  }

  function start() {
    if (isRunning) return;
    isRunning = true;
    hookConsole();
    hookNetwork();
    push("info", "system", "[RTL] Realtime monitoring started");
    bindFirebaseListener();
    tick();
    intervalId = setInterval(tick, 5000);
  }

  function stop() {
    if (intervalId) { clearInterval(intervalId); intervalId = null; }
    isRunning = false;
    push("info", "system", "[RTL] Realtime monitoring paused");
  }

  function isActive() { return isRunning; }

  return { push, subscribe, getAll, getStats, clear, start, stop, isActive, fmtTime };
})();
window.RealtimeLogger = RealtimeLogger;

// Auto-start once DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => RealtimeLogger.start());
} else {
  RealtimeLogger.start();
}

// ─── Realtime Log MODAL — Premium Terminal UI ────────
window.openRealtimeLog = function() {
  if (typeof closeSidebar === "function") closeSidebar();
  const existing = document.getElementById("rtlog-overlay");
  if (existing) { existing.remove(); return; }

  if (!document.getElementById("rtlog-style")) {
    const s = document.createElement("style");
    s.id = "rtlog-style";
    s.textContent = `
      .rtlog-overlay{position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;padding:12px;background:rgba(2,4,14,0.72);backdrop-filter:blur(12px) saturate(160%);}
      .rtlog-panel{width:min(860px,100%);max-height:calc(100vh - 24px);display:flex;flex-direction:column;background:#060b1a;border:1px solid rgba(99,102,241,0.28);border-radius:20px;box-shadow:0 32px 80px rgba(0,0,0,0.85),0 0 0 1px rgba(99,102,241,0.10) inset,0 0 80px rgba(99,102,241,0.07);overflow:hidden;font-family:var(--font,system-ui);}
      /* ── Header ── */
      .rtlog-head{display:flex;align-items:center;justify-content:space-between;padding:12px 16px 11px;border-bottom:1px solid rgba(255,255,255,0.055);flex-shrink:0;background:linear-gradient(90deg,rgba(59,130,246,0.13) 0%,rgba(99,102,241,0.09) 40%,rgba(34,211,238,0.06) 100%);position:relative;gap:10px;}
      .rtlog-head::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:1px;background:linear-gradient(90deg,transparent,rgba(99,102,241,0.55),transparent);}
      .rtlog-title{display:flex;align-items:center;gap:9px;flex:1;min-width:0;}
      .rtlog-pulse{width:9px;height:9px;border-radius:50%;flex-shrink:0;background:#22c55e;box-shadow:0 0 10px rgba(34,197,94,.9),0 0 0 0 rgba(34,197,94,.6);animation:rtPulse 1.8s infinite;}
      .rtlog-pulse.paused{background:#f59e0b;animation:none;box-shadow:0 0 10px rgba(245,158,11,.8);}
      @keyframes rtPulse{0%{box-shadow:0 0 10px rgba(34,197,94,.9),0 0 0 0 rgba(34,197,94,.5)}65%{box-shadow:0 0 8px rgba(34,197,94,.3),0 0 0 11px rgba(34,197,94,0)}100%{box-shadow:0 0 10px rgba(34,197,94,.9),0 0 0 0 rgba(34,197,94,0)}}
      .rtlog-brand{font-size:13px;font-weight:800;color:#e2e8f0;letter-spacing:.2px;text-shadow:0 0 14px rgba(99,102,241,0.5);}
      .rtlog-brand span{color:#818cf8;font-size:10px;font-weight:500;margin-left:5px;vertical-align:middle;}
      .rtlog-status-text{font-size:10px;color:#475569;font-weight:500;white-space:nowrap;}
      .rtlog-head-meta{display:flex;align-items:center;gap:12px;flex-shrink:0;}
      .rtlog-clock-box{display:flex;flex-direction:column;align-items:flex-end;gap:1px;}
      .rtlog-clock{font-family:var(--mono,monospace);font-size:13px;font-weight:700;color:#94a3b8;letter-spacing:.5px;font-variant-numeric:tabular-nums;}
      .rtlog-uptime{font-family:var(--mono,monospace);font-size:9px;color:#475569;letter-spacing:.3px;}
      .rtlog-head-actions{display:flex;gap:5px;flex-shrink:0;}
      /* ── Buttons ── */
      .rtlog-btn{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.09);color:#94a3b8;padding:5px 10px;border-radius:8px;cursor:pointer;font-size:11px;font-weight:600;transition:all .15s;height:28px;display:inline-flex;align-items:center;gap:4px;font-family:var(--mono,monospace);white-space:nowrap;}
      .rtlog-btn:hover{background:rgba(255,255,255,0.09);border-color:rgba(99,102,241,0.4);color:#e2e8f0;box-shadow:0 0 12px rgba(99,102,241,0.18);}
      .rtlog-btn.danger{background:rgba(239,68,68,0.09);border-color:rgba(239,68,68,0.22);color:#f87171;}
      .rtlog-btn.danger:hover{background:rgba(239,68,68,0.16);box-shadow:0 0 12px rgba(239,68,68,0.28);}
      .rtlog-btn.primary{background:linear-gradient(135deg,rgba(59,130,246,0.16),rgba(139,92,246,0.12));border-color:rgba(99,102,241,0.40);color:#a5b4fc;}
      .rtlog-btn.primary:hover{background:linear-gradient(135deg,rgba(59,130,246,0.26),rgba(139,92,246,0.18));box-shadow:0 0 16px rgba(99,102,241,0.30);}
      /* ── Stats ── */
      .rtlog-stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:rgba(255,255,255,0.035);border-bottom:1px solid rgba(255,255,255,0.055);flex-shrink:0;}
      .rtlog-stat{padding:9px 6px 8px;background:#07091a;text-align:center;position:relative;overflow:hidden;cursor:default;}
      .rtlog-stat::before{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--glow-c,rgba(99,102,241,0.3)),transparent);}
      .rtlog-stat.total {--glow-c:rgba(139,92,246,0.4);}
      .rtlog-stat.ok    {--glow-c:rgba(34,197,94,0.4);}
      .rtlog-stat.info  {--glow-c:rgba(59,130,246,0.4);}
      .rtlog-stat.warn  {--glow-c:rgba(245,158,11,0.4);}
      .rtlog-stat.error {--glow-c:rgba(239,68,68,0.4);}
      .rtlog-stat-num{font-family:var(--mono,monospace);font-size:18px;font-weight:800;line-height:1;margin-bottom:4px;transition:transform .2s;}
      .rtlog-stat-bar{height:2px;background:rgba(255,255,255,0.06);border-radius:2px;margin:3px 6px 4px;overflow:hidden;}
      .rtlog-stat-fill{height:100%;border-radius:2px;transition:width .4s ease;min-width:4px;}
      .rtlog-stat-lbl{font-size:9px;color:#64748b;text-transform:uppercase;letter-spacing:.8px;font-weight:600;}
      .rtlog-rate{position:absolute;top:5px;right:8px;font-family:var(--mono,monospace);font-size:8.5px;color:#475569;letter-spacing:.3px;}
      /* ── Toolbar ── */
      .rtlog-toolbar{display:flex;flex-direction:column;gap:0;flex-shrink:0;border-bottom:1px solid rgba(255,255,255,0.055);}
      .rtlog-search-row{display:flex;align-items:center;gap:8px;padding:8px 14px;background:rgba(0,0,0,0.15);}
      .rtlog-search-icon{color:#475569;font-size:12px;flex-shrink:0;}
      .rtlog-search{flex:1;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:7px;padding:5px 10px;font-size:11.5px;color:#cbd5e1;font-family:var(--mono,monospace);outline:none;transition:border-color .15s,box-shadow .15s;}
      .rtlog-search:focus{border-color:rgba(99,102,241,0.45);box-shadow:0 0 0 2px rgba(99,102,241,0.12);}
      .rtlog-search::placeholder{color:#374151;}
      .rtlog-filters{display:flex;gap:4px;padding:7px 14px;overflow-x:auto;flex-shrink:0;scrollbar-width:none;background:linear-gradient(180deg,rgba(99,102,241,0.04),transparent);}
      .rtlog-filters::-webkit-scrollbar{display:none;}
      .rtlog-filter-sep{width:1px;background:rgba(255,255,255,0.07);margin:0 2px;flex-shrink:0;align-self:stretch;}
      .rtlog-fbtn{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);color:#64748b;padding:3px 9px;border-radius:20px;cursor:pointer;font-size:10.5px;white-space:nowrap;transition:all .14s;font-weight:700;font-family:var(--mono,monospace);letter-spacing:.2px;}
      .rtlog-fbtn:hover{background:rgba(255,255,255,0.07);color:#cbd5e1;border-color:rgba(255,255,255,0.16);}
      .rtlog-fbtn.active{border-color:rgba(99,102,241,0.55);color:#c7d2fe;box-shadow:0 0 10px rgba(99,102,241,0.22);}
      .rtlog-fbtn.active{background:linear-gradient(135deg,rgba(59,130,246,0.22),rgba(139,92,246,0.16));}
      .rtlog-fbtn[data-f="ok"].active   {background:linear-gradient(135deg,rgba(34,197,94,0.2),rgba(16,185,129,0.14));border-color:rgba(34,197,94,0.5);color:#86efac;box-shadow:0 0 10px rgba(34,197,94,0.2);}
      .rtlog-fbtn[data-f="warn"].active {background:linear-gradient(135deg,rgba(245,158,11,0.22),rgba(251,191,36,0.16));border-color:rgba(251,191,36,0.5);color:#fde68a;box-shadow:0 0 10px rgba(251,191,36,0.2);}
      .rtlog-fbtn[data-f="error"].active{background:linear-gradient(135deg,rgba(239,68,68,0.24),rgba(220,38,38,0.16));border-color:rgba(239,68,68,0.5);color:#fecaca;box-shadow:0 0 10px rgba(239,68,68,0.22);}
      /* ── Body ── */
      .rtlog-body{flex:1;overflow-y:auto;background:#050810;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:11.5px;line-height:1.6;position:relative;}
      .rtlog-body::-webkit-scrollbar{width:5px;}
      .rtlog-body::-webkit-scrollbar-track{background:transparent;}
      .rtlog-body::-webkit-scrollbar-thumb{background:rgba(99,102,241,0.22);border-radius:3px;}
      .rtlog-body::-webkit-scrollbar-thumb:hover{background:rgba(99,102,241,0.42);}
      /* ── Log lines ── */
      .rtlog-line{display:grid;grid-template-columns:36px 82px 60px 80px 1fr auto;gap:8px;padding:5px 14px 5px 16px;border-bottom:1px solid rgba(255,255,255,0.022);align-items:start;animation:rtFadeIn .22s ease;position:relative;border-left:2px solid transparent;transition:background .12s,border-left-color .12s;cursor:pointer;}
      @keyframes rtFadeIn{from{opacity:0;transform:translateY(-3px)}to{opacity:1;transform:translateY(0)}}
      .rtlog-line:hover{background:rgba(99,102,241,0.055);}
      .rtlog-line:hover .rtl-copy-btn{opacity:1;}
      .rtlog-line.ok    {border-left-color:rgba(34,197,94,0.5);}
      .rtlog-line.info  {border-left-color:rgba(59,130,246,0.5);}
      .rtlog-line.warn  {border-left-color:rgba(245,158,11,0.6);background:linear-gradient(90deg,rgba(245,158,11,0.035),transparent 28%);}
      .rtlog-line.error {border-left-color:rgba(239,68,68,0.7);background:linear-gradient(90deg,rgba(239,68,68,0.055),transparent 28%);}
      .rtlog-line.error:hover{background:linear-gradient(90deg,rgba(239,68,68,0.10),rgba(239,68,68,0.015));}
      .rtlog-line.expanded{background:rgba(99,102,241,0.04)!important;}
      .rtl-linenum{font-size:9px;color:#1e293b;font-weight:700;text-align:right;padding-top:2px;font-variant-numeric:tabular-nums;user-select:none;}
      .rtlog-time{color:#374151;font-size:10px;font-variant-numeric:tabular-nums;padding-top:1px;}
      .rtlog-level{font-weight:800;font-size:9px;text-transform:uppercase;letter-spacing:.5px;padding:2px 6px;border-radius:5px;text-align:center;border:1px solid transparent;width:fit-content;white-space:nowrap;}
      .rtlog-level.ok    {background:rgba(34,197,94,0.13);color:#4ade80;border-color:rgba(34,197,94,0.28);text-shadow:0 0 6px rgba(74,222,128,0.4);}
      .rtlog-level.info  {background:rgba(59,130,246,0.13);color:#60a5fa;border-color:rgba(59,130,246,0.28);text-shadow:0 0 6px rgba(96,165,250,0.4);}
      .rtlog-level.warn  {background:rgba(245,158,11,0.15);color:#fbbf24;border-color:rgba(245,158,11,0.30);}
      .rtlog-level.error {background:rgba(239,68,68,0.16);color:#f87171;border-color:rgba(239,68,68,0.36);text-shadow:0 0 7px rgba(248,113,113,0.5);animation:rtErrPulse 2.2s ease-in-out infinite;}
      @keyframes rtErrPulse{0%,100%{box-shadow:none}50%{box-shadow:0 0 9px rgba(239,68,68,0.35)}}
      .rtlog-kind{font-size:9px;text-transform:uppercase;letter-spacing:.5px;font-weight:700;padding:2px 6px;border-radius:4px;width:fit-content;white-space:nowrap;}
      .rtlog-kind.k-backend  {background:rgba(34,211,238,0.09);color:#67e8f9;border:1px solid rgba(34,211,238,0.18);}
      .rtlog-kind.k-firebase {background:rgba(251,146,60,0.10);color:#fdba74;border:1px solid rgba(251,146,60,0.20);}
      .rtlog-kind.k-api      {background:rgba(168,85,247,0.10);color:#d8b4fe;border:1px solid rgba(168,85,247,0.20);}
      .rtlog-kind.k-network  {background:rgba(20,184,166,0.10);color:#5eead4;border:1px solid rgba(20,184,166,0.20);}
      .rtlog-kind.k-recheck  {background:rgba(99,102,241,0.10);color:#a5b4fc;border:1px solid rgba(99,102,241,0.22);}
      .rtlog-kind.k-security {background:rgba(244,63,94,0.10);color:#fda4af;border:1px solid rgba(244,63,94,0.22);}
      .rtlog-kind.k-vault    {background:rgba(163,230,53,0.09);color:#bef264;border:1px solid rgba(163,230,53,0.20);}
      .rtlog-kind.k-console  {background:rgba(148,163,184,0.08);color:#94a3b8;border:1px solid rgba(148,163,184,0.16);}
      .rtlog-kind.k-system   {background:rgba(100,116,139,0.10);color:#64748b;border:1px solid rgba(100,116,139,0.18);}
      .rtlog-kind.k-js       {background:rgba(234,179,8,0.10);color:#fde047;border:1px solid rgba(234,179,8,0.20);}
      .rtlog-msg{color:#94a3b8;word-break:break-word;white-space:pre-wrap;line-height:1.5;}
      .rtlog-line.error .rtlog-msg{color:#fca5a5;}
      .rtlog-line.warn  .rtlog-msg{color:#fde68a;}
      .rtlog-line.ok    .rtlog-msg{color:#bbf7d0;}
      .rtlog-line.info  .rtlog-msg{color:#bae6fd;}
      .rtlog-msg .rtl-num   {color:#fbbf24;font-weight:700;}
      .rtlog-msg .rtl-url   {color:#67e8f9;text-decoration:underline dotted rgba(103,232,249,0.4);text-underline-offset:2px;}
      .rtlog-msg .rtl-method{color:#a78bfa;font-weight:800;padding:0 4px;border-radius:3px;background:rgba(167,139,250,0.10);}
      .rtlog-msg .rtl-status-ok  {color:#4ade80;font-weight:700;}
      .rtlog-msg .rtl-status-warn{color:#fbbf24;font-weight:700;}
      .rtlog-msg .rtl-status-err {color:#f87171;font-weight:700;}
      .rtlog-msg .rtl-ip  {color:#34d399;font-weight:600;}
      .rtlog-msg .rtl-bracket{color:#475569;}
      /* copy button */
      .rtl-copy-btn{opacity:0;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.25);color:#818cf8;width:20px;height:20px;border-radius:5px;cursor:pointer;font-size:11px;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:all .12s;margin-top:1px;}
      .rtl-copy-btn:hover{background:rgba(99,102,241,0.22);color:#c7d2fe;}
      /* expanded row */
      .rtl-expanded{grid-column:1/-1;background:rgba(99,102,241,0.05);border:1px solid rgba(99,102,241,0.15);border-radius:8px;padding:10px 12px;margin:2px 0 4px;font-family:var(--mono,monospace);font-size:10.5px;display:flex;flex-direction:column;gap:5px;}
      .rtl-exp-row{display:flex;gap:10px;align-items:flex-start;}
      .rtl-exp-key{color:#475569;min-width:72px;flex-shrink:0;font-weight:700;text-transform:uppercase;font-size:9px;letter-spacing:.5px;padding-top:1px;}
      .rtl-exp-val{color:#94a3b8;word-break:break-all;white-space:pre-wrap;flex:1;}
      /* empty state */
      .rtlog-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:64px 20px;color:#1e293b;gap:12px;text-align:center;}
      .rtlog-empty-icon{font-size:40px;filter:grayscale(0.4);opacity:.7;}
      .rtlog-empty-title{font-size:13px;color:#374151;font-weight:600;}
      .rtlog-empty-sub{font-size:11px;color:#1e293b;}
      /* footer */
      .rtlog-foot{padding:9px 14px;border-top:1px solid rgba(255,255,255,0.07);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;background:linear-gradient(180deg,rgba(7,9,26,0.6),#07091a);gap:10px;}
      .rtlog-foot-left{display:flex;align-items:center;gap:12px;flex:1;min-width:0;}
      .rtlog-foot-info{font-size:10px;color:#374151;font-family:var(--mono,monospace);white-space:nowrap;}
      .rtl-live  {color:#4ade80;font-weight:700;}
      .rtl-paused{color:#f59e0b;font-weight:700;}
      .rtl-credit{color:#4338ca;font-weight:700;letter-spacing:.3px;}
      .rtlog-foot-actions{display:flex;gap:5px;flex-shrink:0;}
      /* session divider */
      .rtl-divider{display:flex;align-items:center;gap:10px;padding:6px 16px;font-size:9.5px;color:#1e293b;font-family:var(--mono,monospace);user-select:none;}
      .rtl-divider::before,.rtl-divider::after{content:"";flex:1;height:1px;background:rgba(255,255,255,0.04);}
      /* mobile */
      @media(max-width:640px){
        .rtlog-overlay{padding:0;align-items:stretch;justify-content:stretch;}
        .rtlog-panel{width:100%;max-height:100dvh;border-radius:0;}
        .rtlog-line{grid-template-columns:28px 72px 52px 1fr auto;gap:5px;padding:5px 8px 5px 10px;}
        .rtlog-kind{display:none;}
        .rtlog-clock-box{display:none;}
        .rtlog-stat-num{font-size:15px;}
      }
    `;
    document.head.appendChild(s);
  }

  const overlay = document.createElement("div");
  overlay.id = "rtlog-overlay";
  overlay.className = "rtlog-overlay";
  overlay.innerHTML = `
    <div class="rtlog-panel" role="dialog" aria-label="Realtime Monitor">
      <div class="rtlog-head">
        <div class="rtlog-title">
          <span id="rtlog-pulse" class="rtlog-pulse"></span>
          <div>
            <div class="rtlog-brand">PRIVATE VAULT <span>MONITOR</span></div>
            <div class="rtlog-status-text" id="rtlog-status-text">● Live — Real-time event stream</div>
          </div>
        </div>
        <div class="rtlog-head-meta">
          <div class="rtlog-clock-box">
            <div class="rtlog-clock" id="rtlog-clock">--:--:--</div>
            <div class="rtlog-uptime" id="rtlog-uptime">↑ 0m00s</div>
          </div>
        </div>
        <div class="rtlog-head-actions">
          <button class="rtlog-btn" id="rtlog-toggle">⏸ Pause</button>
          <button class="rtlog-btn" id="rtlog-autoscroll" title="Toggle auto-scroll">↧ Auto</button>
          <button class="rtlog-btn danger" id="rtlog-clear">🗑 Clear</button>
          <button class="rtlog-btn" id="rtlog-close">✕</button>
        </div>
      </div>

      <div class="rtlog-stats" id="rtlog-stats">
        <div class="rtlog-stat total"><div class="rtlog-rate" id="rtlog-rate">0/min</div><div class="rtlog-stat-num" style="color:#c4b5fd;" id="rst-total">0</div><div class="rtlog-stat-bar"><div class="rtlog-stat-fill" id="rsf-total" style="width:100%;background:#6366f1;"></div></div><div class="rtlog-stat-lbl">Total</div></div>
        <div class="rtlog-stat ok">  <div class="rtlog-stat-num" style="color:#4ade80;" id="rst-ok">0</div><div class="rtlog-stat-bar"><div class="rtlog-stat-fill" id="rsf-ok"    style="width:0%;background:#22c55e;"></div></div><div class="rtlog-stat-lbl">OK</div></div>
        <div class="rtlog-stat info"> <div class="rtlog-stat-num" style="color:#60a5fa;" id="rst-info">0</div><div class="rtlog-stat-bar"><div class="rtlog-stat-fill" id="rsf-info"  style="width:0%;background:#3b82f6;"></div></div><div class="rtlog-stat-lbl">Info</div></div>
        <div class="rtlog-stat warn"> <div class="rtlog-stat-num" style="color:#fbbf24;" id="rst-warn">0</div><div class="rtlog-stat-bar"><div class="rtlog-stat-fill" id="rsf-warn"  style="width:0%;background:#f59e0b;"></div></div><div class="rtlog-stat-lbl">Warn</div></div>
        <div class="rtlog-stat error"><div class="rtlog-stat-num" style="color:#f87171;" id="rst-err">0</div><div class="rtlog-stat-bar"><div class="rtlog-stat-fill" id="rsf-err"   style="width:0%;background:#ef4444;"></div></div><div class="rtlog-stat-lbl">Error</div></div>
      </div>

      <div class="rtlog-toolbar">
        <div class="rtlog-search-row">
          <span class="rtlog-search-icon">🔍</span>
          <input type="text" id="rtlog-search" class="rtlog-search" placeholder="Search logs… (keyword, kind, message)" autocomplete="off" spellcheck="false">
        </div>
        <div class="rtlog-filters">
          <button class="rtlog-fbtn active" data-f="all">ALL</button>
          <button class="rtlog-fbtn" data-f="ok">OK</button>
          <button class="rtlog-fbtn" data-f="info">INFO</button>
          <button class="rtlog-fbtn" data-f="warn">WARN</button>
          <button class="rtlog-fbtn" data-f="error">ERROR</button>
          <div class="rtlog-filter-sep"></div>
          <button class="rtlog-fbtn" data-f="vault"    data-kind="1">🗃 Vault</button>
          <button class="rtlog-fbtn" data-f="backend"  data-kind="1">🖥 Backend</button>
          <button class="rtlog-fbtn" data-f="firebase" data-kind="1">🔥 Firebase</button>
          <button class="rtlog-fbtn" data-f="api"      data-kind="1">⚡ API</button>
          <button class="rtlog-fbtn" data-f="network"  data-kind="1">🌐 Network</button>
          <button class="rtlog-fbtn" data-f="security" data-kind="1">🔐 Security</button>
          <button class="rtlog-fbtn" data-f="recheck"  data-kind="1">🔄 Recheck</button>
          <button class="rtlog-fbtn" data-f="console"  data-kind="1">💬 Console</button>
          <button class="rtlog-fbtn" data-f="js"       data-kind="1">🐛 JS</button>
        </div>
      </div>

      <div class="rtlog-body" id="rtlog-body"></div>

      <div class="rtlog-foot">
        <div class="rtlog-foot-left">
          <span class="rtlog-foot-info" id="rtlog-foot-info">0 entries</span>
        </div>
        <div class="rtlog-foot-actions">
          <button class="rtlog-btn primary" id="rtlog-export">↓ Export .log</button>
          <button class="rtlog-btn primary" id="rtlog-runcheck">▶ Check now</button>
        </div>
      </div>
    </div>`;

  document.body.appendChild(overlay);
  overlay.addEventListener("click", e => { if (e.target === overlay) overlay.remove(); });

  // ── State ────────────────────────────────────────────
  let filter     = "all";
  let kindFilter = null;
  let searchQuery= "";
  let autoScroll = true;
  let unsubscribe= null;
  let lineCount  = 0;
  const _openTs  = Date.now();
  const _rateWin = []; // timestamps for events/min

  // ── DOM refs ─────────────────────────────────────────
  const body     = overlay.querySelector("#rtlog-body");
  const footInfo = overlay.querySelector("#rtlog-foot-info");
  const pulse    = overlay.querySelector("#rtlog-pulse");
  const statusTx = overlay.querySelector("#rtlog-status-text");
  const toggleBtn= overlay.querySelector("#rtlog-toggle");
  const autoBtn  = overlay.querySelector("#rtlog-autoscroll");
  const searchEl = overlay.querySelector("#rtlog-search");
  const clockEl  = overlay.querySelector("#rtlog-clock");
  const uptimeEl = overlay.querySelector("#rtlog-uptime");
  const rateEl   = overlay.querySelector("#rtlog-rate");

  // ── Live clock ────────────────────────────────────────
  function updateClock() {
    const now = new Date();
    const pad = n => String(n).padStart(2,"0");
    if (clockEl) clockEl.textContent = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
    if (uptimeEl) {
      const el = Math.floor((Date.now() - _openTs) / 1000);
      const h  = Math.floor(el / 3600);
      const m  = Math.floor((el % 3600) / 60);
      const sc = el % 60;
      uptimeEl.textContent = h > 0 ? `↑ ${h}h ${pad(m)}m` : `↑ ${pad(m)}m${pad(sc)}s`;
    }
  }
  const _clockIv = setInterval(updateClock, 1000);
  updateClock();

  // ── Events/min rate ───────────────────────────────────
  function calcRate() {
    const cut = Date.now() - 60000;
    while (_rateWin.length && _rateWin[0] < cut) _rateWin.shift();
    return _rateWin.length;
  }

  // ── Kind metadata ─────────────────────────────────────
  function kindMeta(k) {
    return ({
      backend: "k-backend", firebase: "k-firebase", api: "k-api",
      network: "k-network", security: "k-security", vault: "k-vault",
      recheck: "k-recheck", console: "k-console",  system: "k-system", js: "k-js"
    })[k] || "k-system";
  }

  // ── Relative time ─────────────────────────────────────
  function relTime(ts) {
    const d = Date.now() - ts;
    if (d < 4000)     return "just now";
    if (d < 60000)    return `${Math.floor(d/1000)}s ago`;
    if (d < 3600000)  return `${Math.floor(d/60000)}m ago`;
    return `${Math.floor(d/3600000)}h ago`;
  }

  // ── Helpers ───────────────────────────────────────────
  function escX(str) {
    return String(str).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);
  }

  function highlight(raw) {
    let s = escX(raw || "");
    s = s.replace(/\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g,'<span class="rtl-method">$1</span>');
    s = s.replace(/(→\s*)(\d{3})/g, (_m, a, code) => {
      const c = +code;
      const cl = c >= 500 ? "rtl-status-err" : c >= 400 ? "rtl-status-warn" : "rtl-status-ok";
      return `${a}<span class="${cl}">${code}</span>`;
    });
    s = s.replace(/\((\d+)ms\)/g, '(<span class="rtl-num">$1</span>ms)');
    s = s.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, '<span class="rtl-ip">$1</span>');
    s = s.replace(/\B(\/[a-zA-Z0-9_\-\/.?=&%+]+)/g, '<span class="rtl-url">$1</span>');
    return s;
  }

  // ── Filter predicate ──────────────────────────────────
  function passes(e) {
    if (filter !== "all" && ["ok","info","warn","error"].includes(filter) && e.level !== filter) return false;
    if (kindFilter && e.kind !== kindFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      if (!e.message.toLowerCase().includes(q) && !e.kind.toLowerCase().includes(q) && !e.level.toLowerCase().includes(q)) return false;
    }
    return true;
  }

  // ── Line HTML ─────────────────────────────────────────
  function lineHTML(e, num) {
    const kc  = kindMeta(e.kind);
    const ts  = RealtimeLogger.fmtTime(e.ts);
    const cpTxt = escX(`[${ts}] [${e.level.toUpperCase()}] [${e.kind.toUpperCase()}] ${e.message}`);
    return `<div class="rtlog-line ${e.level}" data-id="${escX(e.id)}" data-ts="${e.ts}" title="${relTime(e.ts)} — click to expand">
      <span class="rtl-linenum">#${String(num).padStart(3,"0")}</span>
      <span class="rtlog-time">${ts}</span>
      <span class="rtlog-level ${e.level}">${e.level}</span>
      <span class="rtlog-kind ${kc}">${e.kind}</span>
      <span class="rtlog-msg">${highlight(e.message)}</span>
      <button class="rtl-copy-btn" title="Copy" onclick="event.stopPropagation();navigator.clipboard.writeText('${cpTxt.replace(/'/g,"\\'")}').then(()=>this.textContent='✓').catch(()=>{});setTimeout(()=>this.textContent='⎘',1200)">⎘</button>
    </div>`;
  }

  // ── Stats render ──────────────────────────────────────
  function renderStats() {
    const s   = RealtimeLogger.getStats();
    const tot = Math.max(s.total || 1, 1);
    const pct = v => Math.max(Math.round((v||0)/tot*100), v>0?4:0);
    const upd = (id,val) => { const el=overlay.querySelector(id); if(el) el.textContent=val; };
    const bar = (id,p)  => { const el=overlay.querySelector(id); if(el) el.style.width=p+"%"; };
    upd("#rst-total", s.total||0); bar("#rsf-total", 100);
    upd("#rst-ok",    s.ok||0);    bar("#rsf-ok",    pct(s.ok));
    upd("#rst-info",  s.info||0);  bar("#rsf-info",  pct(s.info));
    upd("#rst-warn",  s.warn||0);  bar("#rsf-warn",  pct(s.warn));
    upd("#rst-err",   s.error||0); bar("#rsf-err",   pct(s.error));
    if (rateEl) rateEl.textContent = calcRate() + "/min";
    const all = RealtimeLogger.getAll().filter(passes);
    const live = RealtimeLogger.isActive();
    footInfo.innerHTML = `<span style="color:#374151;font-family:var(--mono,monospace);font-size:10px;">${s.total||0} total &nbsp;·&nbsp; ${all.length} shown &nbsp;·&nbsp; <span class="${live?"rtl-live":"rtl-paused"}">${live?"● live":"⏸ paused"}</span> &nbsp;·&nbsp; <span class="rtl-credit">_RAIHAN</span></span>`;
  }

  // ── Render all entries ────────────────────────────────
  function renderAll() {
    const all = RealtimeLogger.getAll().filter(passes);
    lineCount = 0;
    if (!all.length) {
      body.innerHTML = `<div class="rtlog-empty"><div class="rtlog-empty-icon">📡</div><div class="rtlog-empty-title">No events match</div><div class="rtlog-empty-sub">${searchQuery ? "Try clearing the search." : "Monitoring is " + (RealtimeLogger.isActive() ? "active — waiting for events…" : "paused.")}</div></div>`;
    } else {
      body.innerHTML = `<div class="rtl-divider">— session start —</div>` + all.map(e => lineHTML(e, ++lineCount)).join("");
      if (autoScroll) body.scrollTop = body.scrollHeight;
    }
    renderStats();
  }

  // ── Append single entry ───────────────────────────────
  function appendOne(entry) {
    _rateWin.push(Date.now());
    if (!passes(entry)) { renderStats(); return; }
    const empty = body.querySelector(".rtlog-empty");
    if (empty) { body.innerHTML = `<div class="rtl-divider">— session start —</div>`; lineCount = 0; }
    lineCount++;
    body.insertAdjacentHTML("beforeend", lineHTML(entry, lineCount));
    while (body.children.length > 350) body.removeChild(body.firstChild);
    if (autoScroll) body.scrollTop = body.scrollHeight;
    renderStats();
  }

  // ── Expand on click ───────────────────────────────────
  body.addEventListener("click", ev => {
    const line = ev.target.closest(".rtlog-line");
    if (!line || ev.target.classList.contains("rtl-copy-btn")) return;
    const id = line.dataset.id;
    const entry = RealtimeLogger.getAll().find(x => x.id === id);

    // Collapse if already expanded
    const prev = line.querySelector(".rtl-expanded");
    if (prev) { prev.remove(); line.classList.remove("expanded"); return; }
    line.classList.add("expanded");

    const lvlColor = {ok:"#4ade80",info:"#60a5fa",warn:"#fbbf24",error:"#f87171"}[entry ? entry.level : "info"] || "#94a3b8";
    const det = document.createElement("div");
    det.className = "rtl-expanded";
    det.innerHTML = entry ? `
      <div class="rtl-exp-row"><span class="rtl-exp-key">timestamp</span><span class="rtl-exp-val">${new Date(entry.ts).toISOString()}</span></div>
      <div class="rtl-exp-row"><span class="rtl-exp-key">relative</span><span class="rtl-exp-val">${relTime(entry.ts)}</span></div>
      <div class="rtl-exp-row"><span class="rtl-exp-key">level</span><span class="rtl-exp-val" style="color:${lvlColor};font-weight:700;">${entry.level.toUpperCase()}</span></div>
      <div class="rtl-exp-row"><span class="rtl-exp-key">kind</span><span class="rtl-exp-val">${entry.kind}</span></div>
      <div class="rtl-exp-row"><span class="rtl-exp-key">message</span><span class="rtl-exp-val" style="color:#e2e8f0;">${escX(entry.message)}</span></div>
      ${entry.meta ? `<div class="rtl-exp-row"><span class="rtl-exp-key">meta</span><span class="rtl-exp-val" style="font-size:9.5px;color:#64748b;">${escX(JSON.stringify(entry.meta,null,2))}</span></div>` : ""}
      <div class="rtl-exp-row"><span class="rtl-exp-key">entry id</span><span class="rtl-exp-val" style="font-size:9px;color:#374151;">${escX(entry.id)}</span></div>
    ` : `<div class="rtl-exp-row"><span class="rtl-exp-val" style="color:#475569;">Entry not found in buffer.</span></div>`;
    line.insertAdjacentElement("beforeend", det);
  });

  // ── Button wiring ─────────────────────────────────────
  overlay.querySelector("#rtlog-close").onclick = () => {
    clearInterval(_clockIv);
    overlay.remove();
  };

  overlay.querySelector("#rtlog-clear").onclick = () => {
    RealtimeLogger.clear();
    lineCount = 0;
    renderAll();
  };

  overlay.querySelector("#rtlog-export").onclick = () => {
    const logs = RealtimeLogger.getAll();
    const lines = logs.map(e => {
      const ts = RealtimeLogger.fmtTime(e.ts);
      return `[${ts}] [${e.level.toUpperCase().padEnd(5)}] [${e.kind.toUpperCase().padEnd(9)}] ${e.message}`;
    });
    const header = `# Private Vault — Realtime Log Export\n# Exported: ${new Date().toISOString()}\n# Entries: ${logs.length}\n${"─".repeat(72)}\n\n`;
    const blob = new Blob([header + lines.join("\n")], { type: "text/plain;charset=utf-8" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = `vault-log-${Date.now()}.log`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    RealtimeLogger.push("ok", "system", `📥 Log exported — ${logs.length} entries`);
  };

  overlay.querySelector("#rtlog-runcheck").onclick = () => {
    RealtimeLogger.push("info", "system", "▶ Manual health check triggered");
    if (!RealtimeLogger.isActive()) RealtimeLogger.start();
  };

  toggleBtn.onclick = () => {
    if (RealtimeLogger.isActive()) {
      RealtimeLogger.stop();
      toggleBtn.innerHTML = "▶ Resume";
      pulse.classList.add("paused");
      statusTx.textContent = "⏸ Paused — monitoring stopped";
    } else {
      RealtimeLogger.start();
      toggleBtn.innerHTML = "⏸ Pause";
      pulse.classList.remove("paused");
      statusTx.textContent = "● Live — Real-time event stream";
    }
  };

  autoBtn.onclick = () => {
    autoScroll = !autoScroll;
    autoBtn.style.background = autoScroll ? "rgba(59,130,246,0.14)" : "";
    autoBtn.style.borderColor = autoScroll ? "rgba(99,102,241,0.4)" : "";
    autoBtn.style.color = autoScroll ? "#93c5fd" : "";
    if (autoScroll) body.scrollTop = body.scrollHeight;
  };
  autoBtn.style.background = "rgba(59,130,246,0.14)";
  autoBtn.style.borderColor= "rgba(99,102,241,0.4)";
  autoBtn.style.color = "#93c5fd";

  // Search
  searchEl.oninput = () => { searchQuery = searchEl.value.trim(); renderAll(); };
  searchEl.onkeydown = e => { if (e.key === "Escape") { searchEl.value = ""; searchQuery = ""; renderAll(); } };

  // Filter buttons
  overlay.querySelectorAll(".rtlog-fbtn").forEach(b => {
    b.onclick = () => {
      const f = b.dataset.f;
      const isKind = b.dataset.kind === "1";
      if (isKind) {
        kindFilter = (kindFilter === f) ? null : f;
        overlay.querySelectorAll('.rtlog-fbtn[data-kind="1"]').forEach(x => x.classList.remove("active"));
        if (kindFilter) b.classList.add("active");
      } else {
        filter = f;
        overlay.querySelectorAll('.rtlog-fbtn:not([data-kind])').forEach(x => x.classList.remove("active"));
        b.classList.add("active");
      }
      renderAll();
    };
  });

  // Live subscription
  unsubscribe = RealtimeLogger.subscribe((entry, cleared) => {
    if (cleared) { lineCount = 0; renderAll(); return; }
    if (entry) appendOne(entry);
  });

  // Cleanup on remove
  const obs = new MutationObserver(() => {
    if (!document.body.contains(overlay)) {
      clearInterval(_clockIv);
      if (unsubscribe) unsubscribe();
      obs.disconnect();
    }
  });
  obs.observe(document.body, { childList: true });

  if (!RealtimeLogger.isActive()) {
    toggleBtn.innerHTML = "▶ Resume";
    pulse.classList.add("paused");
    statusTx.textContent = "⏸ Paused — monitoring stopped";
  }

  renderAll();
};

// Capture global JS errors → realtime log
window.addEventListener("error", (e) => {
  try { RealtimeLogger.push("error", "js", `${e.message} @ ${(e.filename||"").split("/").pop()}:${e.lineno||"?"}`); } catch(_) {}
});
window.addEventListener("unhandledrejection", (e) => {
  try { RealtimeLogger.push("error", "js", `Promise rejected: ${e.reason && e.reason.message || e.reason}`); } catch(_) {}
});

// ══════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════
initAdmin();
