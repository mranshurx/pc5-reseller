'use strict';
const dbg = window.__dbg || function () {};
const CFG = { KEYS_REPO:'mranshurx/pc5-android', DATA_REPO:'mranshurx/pc5-reseller', BRANCH:'main',
  KEYS_PATH:'data/keys.json', DATA_PATH:'data/resellers.json',
  ADMIN_PASSWORD:'pc5admin', // change this — it ships in plaintext
  SHARED_TOKEN:'', PREFIX:'PC5-', ALPHABET:'ABCDEFGHJKLMNPQRSTUVWXYZ23456789' };

const PLANS = [['1h',1,.5],['3h',3,2],['6h',6,3],['12h',12,5],['1d',24,7],['3d',72,14],
  ['7d',168,25],['14d',336,30],['30d',720,80]].map(([label,hours,cost]) => ({label,hours,cost}));

const IS_ADMIN = document.documentElement.dataset.route === 'admin';
const HOME = './';
const app = document.getElementById('app');
const $ = (s,r=document) => r.querySelector(s);
const $$ = (s,r=document) => [...r.querySelectorAll(s)];
const sleep = ms => new Promise(r => setTimeout(r, ms));
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

/* ---------- storage ---------- */
const LS = { session:'pc5_session', admin:'pc5_admin', token:'pc5_admin_token' };
const tokenKey = id => 'pc5_rtoken_' + id;          // per-reseller token, local only
const ADMIN_TTL = 12 * 3600e3;                       // owner flag expires after 12h

const getSession = () => { try { return JSON.parse(localStorage.getItem(LS.session) || 'null'); } catch { return null; } };
const setSession = r => localStorage.setItem(LS.session, JSON.stringify({ id:r.id }));
const clearSession = () => localStorage.removeItem(LS.session);

const localToken = id => (id ? localStorage.getItem(tokenKey(id)) || '' : '');
const setLocalToken = (id, t) => t ? localStorage.setItem(tokenKey(id), t) : localStorage.removeItem(tokenKey(id));

const isAdmin = () => {
  try {
    const v = JSON.parse(localStorage.getItem(LS.admin) || 'null');
    if (!v || typeof v !== 'object' || !v.exp || v.exp < Date.now()) {
      localStorage.removeItem(LS.admin); return false;
    }
    return true;
  } catch { localStorage.removeItem(LS.admin); return false; }
};
const setAdmin = () => localStorage.setItem(LS.admin, JSON.stringify({ exp: Date.now() + ADMIN_TTL }));
const clearAdmin = () => localStorage.removeItem(LS.admin);

/* ---------- ui ---------- */
function toast(m, k='') {
  const el = document.createElement('div');
  el.className = 'toast ' + k; el.textContent = m;
  $('#toasts').append(el); setTimeout(() => el.remove(), 6000);
}
const fmtDate = i => i ? new Date(i).toLocaleString() : '—';
function countdown(iso) {
  if (!iso) return 'not started';
  const ms = new Date(iso) - Date.now();
  if (ms <= 0) return 'expired';
  const s = Math.floor(ms/1000), d = Math.floor(s/86400), h = Math.floor(s%86400/3600),
        m = Math.floor(s%3600/60), x = s%60;
  return (d ? d+'d ' : '') + (d || h ? h+'h ' : '') + m+'m '+x+'s';
}
function show(el, on) {
  if (!el) return;
  el.classList.toggle('hide', !on);
  if (on) el.style.setProperty('display', 'block', 'important');
  else el.style.removeProperty('display');
}

/* ---------- crypto ---------- */
const te = new TextEncoder();
const hex2buf = h => new Uint8Array(h.match(/.{2}/g).map(b => parseInt(b,16)));
const buf2hex = b => [...b].map(x => x.toString(16).padStart(2,'0')).join('');
const sha256 = async s => buf2hex(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(s))));
async function pbkdf2(pw, salt, iter) {
  const k = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const b = await crypto.subtle.deriveBits({ name:'PBKDF2', salt:hex2buf(salt), iterations:iter, hash:'SHA-256' }, k, 256);
  return buf2hex(new Uint8Array(b));
}
async function hashPassword(pw) {
  if (!crypto.subtle) return 'fb$' + await sha256(pw);
  const s = buf2hex(crypto.getRandomValues(new Uint8Array(16)));
  return `pbkdf2$120000$${s}$${await pbkdf2(pw, s, 120000)}`;
}
async function verifyPassword(pw, st) {
  if (!st) return false;
  if (st.startsWith('fb$')) return ('fb$' + await sha256(pw)) === st;
  const [, i, s, h] = st.split('$');
  if (!h) return false;
  return (await pbkdf2(pw, s, +i)) === h;
}
const dummyHash = async pw => { try { await pbkdf2(pw, '00'.repeat(16), 120000); } catch {} };

/* ---------- github ---------- */
class Conflict extends Error {
  constructor(path, status, detail) {
    super(`${path} — HTTP ${status}${detail ? ': ' + detail : ''}`);
    this.path = path; this.status = status; this.detail = detail;
  }
}

const b64e = s => {
  const b = te.encode(s); let o = '';
  for (let i = 0; i < b.length; i += 0x8000) o += String.fromCharCode.apply(null, b.subarray(i, i+0x8000));
  return btoa(o);
};
const b64d = s => {
  const b = atob(String(s).replace(/\s/g,'')); const u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return new TextDecoder().decode(u);
};
const authHeaders = (t, j) => {
  const h = { Accept:'application/vnd.github+json' };
  if (t) h.Authorization = 'Bearer ' + t;
  if (j) h['Content-Type'] = 'application/json';
  return h;
};

// Local token wins, then the token stored on the record, then the shared one.
const writeToken = r =>
  localToken(r && r.id) || (r && r.token) || localStorage.getItem(LS.token) || CFG.SHARED_TOKEN || '';

const defaultFor = path => path.endsWith('keys.json') ? { maintenance:{}, keys:[] } : { resellers:[] };

// Unique URL + no-store: GitHub's CDN otherwise hands back a stale sha forever.
const contentsUrl = (repo, path) =>
  `https://api.github.com/repos/${repo}/contents/${path}?ref=${CFG.BRANCH}&_=${Date.now()}${Math.random().toString(36).slice(2,8)}`;
const noStore = { cache:'no-store' };

async function currentSha(repo, path, token) {
  const r = await fetch(contentsUrl(repo, path), { headers: authHeaders(token), ...noStore });
  if (!r.ok) return null;
  const j = await r.json();
  return j.sha || null;
}

async function readJson(repo, path, token) {
  let r = null;
  try { r = await fetch(contentsUrl(repo, path), { headers: authHeaders(token), ...noStore }); } catch { /* offline */ }

  if (r && r.status === 404) return { data: defaultFor(path), sha: null };

  if (r && r.ok) {
    const j = await r.json();
    return { data: JSON.parse(b64d(j.content)), sha: j.sha };
  }

  dbg(`read ${path} API failed (${r ? r.status : 'network'}) — raw fallback`);
  const raw = await fetch(`https://raw.githubusercontent.com/${repo}/${CFG.BRANCH}/${path}?_=${Date.now()}`, noStore);
  if (!raw.ok) throw new Error(`read ${path}: HTTP ${r ? r.status : 'network'}`);
  const data = JSON.parse(await raw.text());
  const sha = await currentSha(repo, path, token);
  if (!sha && r && (r.status === 401 || r.status === 403))
    throw new Error(`read ${path}: HTTP ${r.status} — token cannot read ${repo}`);
  return { data, sha };
}

async function writeJson(repo, path, data, sha, msg, token) {
  if (!token) throw new Error('No GitHub token — save a token first.');
  if (!sha) sha = await currentSha(repo, path, token);
  const body = { message:msg, content:b64e(JSON.stringify(data, null, 2)), branch:CFG.BRANCH };
  if (sha) body.sha = sha;
  const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}`,
    { method:'PUT', headers:authHeaders(token, true), body:JSON.stringify(body), ...noStore });

  if (r.status === 409 || r.status === 422) {
    let detail = ''; try { detail = (await r.json()).message || ''; } catch {}
    throw new Conflict(path, r.status, detail);
  }
  if (r.status === 401 || r.status === 403)
    throw new Error(`write ${path}: HTTP ${r.status} — token needs Contents: write on ${repo}`);
  if (r.status === 404)
    throw new Error(`write ${path}: HTTP 404 — token has no access to ${repo}, or the data/ folder is missing`);
  if (!r.ok) throw new Error(`write ${path}: HTTP ${r.status} ${(await r.text()).slice(0,150)}`);
  return r.json();
}

async function withRetry(fn, n = 6) {
  let last;
  for (let i = 0; i < n; i++) {
    try { return await fn(); }
    catch (e) { last = e; if (!(e instanceof Conflict)) throw e; await sleep(300*1.7**i + Math.random()*200); }
  }
  throw last;
}
const loadResellers = t => readJson(CFG.DATA_REPO, CFG.DATA_PATH, t);
const loadKeys = t => readJson(CFG.KEYS_REPO, CFG.KEYS_PATH, t);

async function mutateResellers(mut, token, msg = 'reseller update') {
  return withRetry(async () => {
    const { data, sha } = await loadResellers(token);
    if (!Array.isArray(data.resellers)) data.resellers = [];
    const out = mut(data);
    if (out === false) return false;
    await writeJson(CFG.DATA_REPO, CFG.DATA_PATH, data, sha, msg, token);
    return out === undefined ? true : out;
  });
}

/* ---------- minting ---------- */
const randomKey = () => CFG.PREFIX + Array.from(crypto.getRandomValues(new Uint8Array(6)),
  b => CFG.ALPHABET[b % CFG.ALPHABET.length]).join('');

async function mintKey(rec, plan, opt) {
  const token = writeToken(rec);
  if (!token) throw new Error('No GitHub token saved.');
  if ((rec.credits ?? 0) < plan.cost) throw new Error('Not enough credits.');
  const now = Date.now();
  const p = { key:null, plan:plan.label, durationHours:plan.hours, maxDevices:opt.multi ? 0 : 1,
    cost:plan.cost, resellerId:rec.id, reseller:rec.username, createdAt:new Date(now).toISOString(),
    startedAt: opt.immediate ? new Date(now).toISOString() : null, activatedAt:null,
    expiresAt: opt.immediate ? new Date(now + plan.hours*3600e3).toISOString() : null };
  const key = await withRetry(async () => {
    const { data, sha } = await loadKeys(token);
    if (!Array.isArray(data.keys)) data.keys = [];
    if (!data.maintenance) data.maintenance = {};
    let k = randomKey();
    while (data.keys.some(x => x.key === k)) k = randomKey();
    p.key = k; data.keys.push(p);
    await writeJson(CFG.KEYS_REPO, CFG.KEYS_PATH, data, sha, `mint ${k} (${plan.label})`, token);
    return k;
  });
  try {
    await mutateResellers(d => {
      const r = d.resellers.find(x => x.id === rec.id);
      if (!r) return false;
      r.credits = +((r.credits ?? 0) - plan.cost).toFixed(2);
      r.keys = r.keys || [];
      r.keys.push({ key, plan:plan.label, cost:plan.cost, createdAt:p.createdAt, revoked:false });
    }, token);
  } catch { toast(`Key ${key} written but credit deduction failed — refresh.`, 'err'); }
  return key;
}

const ip = async () => { try { return (await (await fetch('https://api.ipify.org?format=json')).json()).ip || ''; } catch { return ''; } };

/* ---------- views ---------- */
const plansHTML = () => PLANS.map(p =>
  `<button data-plan="${p.label}"><b>${p.label}</b><small>${p.cost} cr</small></button>`).join('');

function viewReseller() {
  return `
  <div id="ownerNotice" class="ownerbar hide">
    <p><b>Owner mode</b> — console lives at <code>/vips</code>.</p>
    <a class="btn primary" href="vips">Open console</a>
    <button id="asReseller" class="sm">Dismiss</button>
  </div>
  <div id="authPanel">
    <h1>Reseller sign in</h1>
    <p class="sub">Accounts are issued by the owner.</p>
    <form id="loginForm" class="card narrow">
      <label for="loginUser">Username</label>
      <input id="loginUser" autocomplete="username" required>
      <label for="loginPass">Password</label>
      <input id="loginPass" type="password" autocomplete="current-password" required>
      <button class="primary" type="submit">Sign in</button>
    </form>
  </div>
  <div id="resellerPanel" class="hide">
    <h1 id="hello">—</h1>
    <p class="sub">Credits: <b id="credits">0</b><button id="signOut" class="sm">Sign out</button></p>
    <div class="card">
      <h2>GitHub token</h2>
      <p class="muted">Fine-grained PAT on <code>pc5-android</code> with <code>Contents: Read and write</code>. Saved on this device only.</p>
      <div class="row"><input id="tokenInput" type="password" placeholder="ghp_…" class="grow">
        <button id="saveToken">Save</button><button id="clearToken" class="sm">Clear</button></div>
      <p id="tokenState" class="muted sm-note"></p>
    </div>
    <div class="card">
      <h2>Mint a key</h2>
      <div class="plans" id="plans">${plansHTML()}</div>
      <div class="toggles">
        <label><input type="checkbox" id="optImmediate" checked> Start immediately</label>
        <label><input type="checkbox" id="optMulti"> Multi-device</label>
      </div>
    </div>
    <div class="card">
      <h2>My keys</h2>
      <table><thead><tr><th>Key</th><th>Plan</th><th>Created</th><th>Expiry</th><th>Cost</th><th></th></tr></thead>
      <tbody id="myKeys"><tr><td colspan="6" class="muted">No keys yet.</td></tr></tbody></table>
    </div>
  </div>`;
}

function viewAdmin() {
  return `
  <div id="adminGate" class="narrow">
    <h1>Owner console</h1>
    <p class="sub">Password required.</p>
    <form id="gateForm" class="card">
      <label for="gatePass">Password</label>
      <input id="gatePass" type="password" required>
      <button class="primary" type="submit">Unlock</button>
    </form>
  </div>
  <div id="adminConsole" class="hide">
    <h1>Owner console</h1>
    <p class="sub"><button id="adminOut" class="sm">Lock</button></p>
    <div class="stats" id="stats"></div>
    <div class="card">
      <h2>Owner GitHub token</h2>
      <p class="muted">Needs <code>Contents: Read and write</code> on <code>pc5-android</code> AND <code>pc5-reseller</code>. One token, both repos.</p>
      <div class="row"><input id="adminToken" type="password" placeholder="ghp_…" class="grow">
        <button id="saveAdminToken">Save</button><button id="testAdminToken">Test read</button>
        <button id="writeTest">Test write</button></div>
      <p id="tokenDiag" class="muted sm-note"></p>
    </div>
    <div class="card">
      <h2>Create reseller</h2>
      <div class="grid">
        <div><label for="newUser">Username</label><input id="newUser" placeholder="3-20 chars, a-z 0-9 _"></div>
        <div><label for="newPass">Password</label>
          <div class="row"><input id="newPass" class="grow"><button type="button" id="genPass">Generate</button></div></div>
        <div><label for="newCredits">Starting credits</label>
          <input id="newCredits" type="number" min="0" step="0.5" value="0"></div>
        <div><label for="newToken">Their token (blank = shared)</label>
          <input id="newToken" type="password" placeholder="optional"></div>
      </div>
      <button class="primary" id="createReseller">Create account</button>
    </div>
    <h2 class="gap">Resellers</h2>
    <div id="resellerList"></div>
  </div>`;
}

/* ---------- reseller wiring ---------- */
let currentRecord = null;

function wireReseller() {
  $('#loginForm').addEventListener('submit', async e => {
    e.preventDefault();
    const btn = e.target.querySelector('button'); btn.disabled = true;
    try {
      const u = $('#loginUser').value.trim().toLowerCase(), pw = $('#loginPass').value;
      const { data } = await loadResellers(writeToken(null));
      const r = (data.resellers || []).find(x => x.username === u);
      const ok = r ? await verifyPassword(pw, r.password) : (await dummyHash(pw), false);
      if (!r || !ok) throw new Error('Invalid credentials.');
      if (r.banned) throw new Error('Account banned.');
      setSession(r); e.target.reset();
      mutateResellers(d => {
        const t = d.resellers.find(x => x.id === r.id);
        if (t) {
          t.logins = t.logins || [];
          t.logins.unshift({ at:new Date().toISOString(), ip:'', ua:navigator.userAgent });
          t.logins.length = Math.min(t.logins.length, 20);
        }
      }, writeToken(r), 'login').catch(() => {});
      ip().then(a => { if (!a) return; mutateResellers(d => {
        const t = d.resellers.find(x => x.id === r.id);
        if (t && t.logins && t.logins[0]) t.logins[0].ip = a;
      }, writeToken(r), 'login ip').catch(() => {}); });
      openPanel(r);
    } catch (err) { toast(err.message, 'err'); }
    finally { btn.disabled = false; }
  });

  $('#asReseller').addEventListener('click', () => {
    clearAdmin();
    $('#navAdmin')?.classList.add('hide');
    show($('#ownerNotice'), false);
    show($('#authPanel'), true);
  });

  $('#signOut').addEventListener('click', () => { clearSession(); location.href = HOME; });

  $('#plans').addEventListener('click', e => {
    const b = e.target.closest('[data-plan]');
    if (!b) return;
    onMint(PLANS.find(p => p.label === b.dataset.plan), b);
  });

  $('#myKeys').addEventListener('click', async e => {
    const b = e.target.closest('[data-copy]');
    if (!b) return;
    try { await navigator.clipboard.writeText(b.dataset.copy); toast('Copied', 'ok'); }
    catch { toast('Copy failed', 'err'); }
  });

  // Local save FIRST (always works), repo persist is best-effort.
  $('#saveToken').addEventListener('click', async () => {
    if (!currentRecord) return;
    const t = $('#tokenInput').value.trim();
    if (!t) return toast('Paste a token.', 'err');

    setLocalToken(currentRecord.id, t);
    currentRecord.token = t;
    $('#tokenInput').value = '';
    renderTokenState();
    refreshMine();

    if (!/^(gh[pousr]_|github_pat_)/.test(t)) {
      toast('Saved on this device, but that does not look like a GitHub token.', 'err');
      return;
    }

    const btn = $('#saveToken'); btn.disabled = true;
    try {
      const r = await fetch('https://api.github.com/user', { headers: authHeaders(t), ...noStore });
      if (!r.ok) throw new Error(`GitHub rejected the token (HTTP ${r.status}).`);
      toast('Token saved.', 'ok');
      try {
        await mutateResellers(d => {
          const x = d.resellers.find(y => y.id === currentRecord.id); if (x) x.token = t;
        }, t, 'save token');
      } catch { toast('Token works here, but could not be stored on the server.', 'err'); }
    } catch (err) { toast(err.message, 'err'); }
    finally { btn.disabled = false; }
  });

  $('#clearToken').addEventListener('click', () => {
    if (!currentRecord) return;
    setLocalToken(currentRecord.id, '');
    currentRecord.token = '';
    renderTokenState();
    toast('Token cleared on this device.', 'ok');
  });
}

function openPanel(rec) {
  currentRecord = rec;
  rec.token = localToken(rec.id) || rec.token || '';   // hydrate from device
  show($('#authPanel'), false);
  show($('#ownerNotice'), false);
  show($('#resellerPanel'), true);
  $('#hello').textContent = 'Signed in as ' + rec.username;
  renderTokenState(); refreshMine(); startTicker();
}

function renderTokenState() {
  const t = writeToken(currentRecord);
  $('#tokenState').textContent = t
    ? `Token active (…${t.slice(-6)}) — minting enabled.`
    : 'No token saved. Minting is blocked.';
  $('#credits').textContent = currentRecord?.credits ?? 0;
}

async function onMint(plan, btn) {
  if (!currentRecord || !plan) return;
  if ((currentRecord.credits ?? 0) < plan.cost) return toast('Not enough credits.', 'err');
  if (!writeToken(currentRecord)) return toast('Save a GitHub token first.', 'err');
  btn.disabled = true;
  try {
    const key = await mintKey(currentRecord, plan,
      { immediate:$('#optImmediate').checked, multi:$('#optMulti').checked });
    toast('Minted ' + key, 'ok');
    const fresh = await reloadRecord(); if (fresh) currentRecord = fresh;
    refreshMine();
  } catch (err) { toast(err.message, 'err'); }
  finally { btn.disabled = false; }
}

async function reloadRecord() {
  const s = getSession(); if (!s) return null;
  const { data } = await loadResellers(writeToken(null));
  const r = (data.resellers || []).find(x => x.id === s.id);
  if (!r) return null;
  if (r.banned) { clearSession(); toast('Account banned.', 'err'); }
  r.token = localToken(r.id) || r.token || '';
  $('#credits').textContent = r.credits ?? 0; renderTokenState();
  return r;
}

async function refreshMine() {
  if (!currentRecord) return;
  try {
    const { data } = await loadKeys(writeToken(currentRecord));
    const mine = (data.keys || []).filter(k => k.resellerId === currentRecord.id).reverse();
    const tb = $('#myKeys');
    if (!mine.length) { tb.innerHTML = '<tr><td colspan="6" class="muted">No keys yet.</td></tr>'; return; }
    tb.innerHTML = mine.map(k => {
      const exp = k.expiresAt, live = exp && new Date(exp) > new Date();
      return `<tr><td><code>${esc(k.key)}</code></td><td>${esc(k.plan)}</td>
      <td class="muted">${esc(fmtDate(k.createdAt))}</td>
      <td><span class="pill ${live?'live':(exp?'dead':'pend')}" data-exp="${esc(exp||'')}">${esc(countdown(exp))}</span></td>
      <td>${esc(k.cost)} cr</td>
      <td><button data-copy="${esc(k.key)}" class="sm">Copy</button></td></tr>`;
    }).join('');
  } catch {}
}

/* ---------- admin wiring ---------- */
function wireAdmin() {
  $('#gateForm').addEventListener('submit', e => {
    e.preventDefault();
    if ($('#gatePass').value !== CFG.ADMIN_PASSWORD) return toast('Wrong password.', 'err');
    setAdmin();
    $('#navAdmin')?.classList.remove('hide');
    openConsole();
  });
  $('#adminOut').addEventListener('click', () => {
    clearAdmin();
    show($('#adminConsole'), false);
    show($('#adminGate'), true);
    $('#gatePass').value = '';
  });
  $('#saveAdminToken').addEventListener('click', async () => {
    const t = $('#adminToken').value.trim();
    if (!t) return toast('Paste a token.', 'err');
    localStorage.setItem(LS.token, t);
    toast('Owner token saved.', 'ok');
    refreshAdmin();
  });
  $('#testAdminToken').addEventListener('click', async () => {
    const t = (localStorage.getItem(LS.token) || CFG.SHARED_TOKEN || '').trim();
    const out = $('#tokenDiag');
    if (!t) { out.textContent = 'No token saved.'; return toast('Save the owner token first.', 'err'); }
    out.textContent = 'Testing read…';
    const lines = [];
    for (const [repo, path] of [[CFG.DATA_REPO, CFG.DATA_PATH], [CFG.KEYS_REPO, CFG.KEYS_PATH]]) {
      let s = 'network error';
      try {
        const r = await fetch(contentsUrl(repo, path), { headers: authHeaders(t), ...noStore });
        s = r.ok ? 'read OK' : `HTTP ${r.status}`;
      } catch {}
      lines.push(`${repo}/${path}: ${s}`);
    }
    out.textContent = lines.join('  ·  ');
    const good = lines.every(l => l.endsWith('OK'));
    toast(good ? 'Token can read both repos.' : 'Token cannot read both repos — see diagnostics.', good ? 'ok' : 'err');
  });
  $('#writeTest').addEventListener('click', async () => {
    const t = (localStorage.getItem(LS.token) || CFG.SHARED_TOKEN || '').trim();
    const out = $('#tokenDiag');
    if (!t) { out.textContent = 'No token saved.'; return toast('Save the owner token first.', 'err'); }
    out.textContent = 'Testing write round-trip…';
    try {
      const { data, sha } = await loadResellers(t);
      const r = await fetch(`https://api.github.com/repos/${CFG.DATA_REPO}/contents/${CFG.DATA_PATH}`, {
        method:'PUT', headers: authHeaders(t, true), ...noStore,
        body: JSON.stringify({ message:'write test', content: b64e(JSON.stringify(data, null, 2)),
          branch: CFG.BRANCH, ...(sha ? { sha } : {}) }) });
      if (r.ok) {
        out.textContent = `write OK (sha ${sha ? sha.slice(0,7) : 'none — file created'})`;
        toast('Write works.', 'ok'); refreshAdmin(); return;
      }
      let m = ''; try { m = (await r.json()).message || ''; } catch {}
      out.textContent = `write FAILED — HTTP ${r.status}: ${m || 'no message'}`;
      toast(`Write failed: HTTP ${r.status}`, 'err');
    } catch (err) { out.textContent = 'write test error: ' + err.message; toast(err.message, 'err'); }
  });
  $('#genPass').addEventListener('click', () => {
    const c = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    $('#newPass').value = Array.from(crypto.getRandomValues(new Uint8Array(14)), b => c[b % c.length]).join('');
  });
  $('#createReseller').addEventListener('click', async e => {
    e.preventDefault();
    const token = localStorage.getItem(LS.token) || CFG.SHARED_TOKEN;
    if (!token) return toast('Save the owner token first.', 'err');
    const u = $('#newUser').value.trim().toLowerCase(), pw = $('#newPass').value,
      cr = Math.max(0, Number($('#newCredits').value || 0)), tk = $('#newToken').value.trim();
    if (!/^[a-z0-9_]{3,20}$/.test(u)) return toast('Username: 3-20 chars, a-z 0-9 _ only.', 'err');
    if (pw.length < 8) return toast('Password needs 8+ characters.', 'err');
    const btn = e.target; btn.disabled = true;
    try {
      const hash = await hashPassword(pw);
      const ok = await mutateResellers(d => {
        if (d.resellers.some(r => r.username === u)) return false;
        d.resellers.push({ id:crypto.randomUUID(), username:u, password:hash, token:tk || null,
          credits:cr, banned:false, createdAt:new Date().toISOString(), createdBy:'admin', keys:[], logins:[] });
      }, token, `create reseller ${u}`);
      if (!ok) throw new Error('Username already exists.');
      toast(`Created ${u} — hand them the password.`, 'ok');
      $('#newUser').value = ''; $('#newPass').value = ''; $('#newToken').value = ''; $('#newCredits').value = '0';
      refreshAdmin();
    } catch (err) { toast(err.message, 'err'); }
    finally { btn.disabled = false; }
  });
  $('#resellerList').addEventListener('click', onAdminAction);
}

function openConsole() {
  show($('#adminGate'), false);
  show($('#adminConsole'), true);
  const t = localStorage.getItem(LS.token); if (t) $('#adminToken').value = t;
  refreshAdmin(); startTicker();
}

async function refreshAdmin() {
  const token = localStorage.getItem(LS.token) || CFG.SHARED_TOKEN;
  if (!token) { $('#stats').innerHTML = '<div class="stat"><b>!</b><span>save owner token</span></div>'; return; }
  try {
    const [{ data: rd }, { data: kd }] = await Promise.all([loadResellers(token), loadKeys(token)]);
    const rs = rd.resellers || [], ks = kd.keys || [], day = Date.now() - 86400e3;
    $('#stats').innerHTML = [['resellers', rs.length],
      ['active 24h', rs.filter(r => (r.logins || []).some(l => new Date(l.at) > day)).length],
      ['keys issued', ks.length],
      ['still valid', ks.filter(k => k.expiresAt && new Date(k.expiresAt) > new Date()).length],
      ['credits held', rs.reduce((a, r) => a + (r.credits ?? 0), 0)]]
      .map(([l, v]) => `<div class="stat"><b>${v}</b><span>${l}</span></div>`).join('');
    const box = $('#resellerList');
    if (!rs.length) { box.innerHTML = '<p class="muted">No resellers yet.</p>'; return; }
    box.innerHTML = rs.map(r => {
      const rk = ks.filter(k => k.resellerId === r.id);
      const lg = (r.logins || []).slice(0, 5).map(l =>
        `<div class="log">${esc(fmtDate(l.at))} · ${esc(l.ip || '?')} · ${esc((l.ua || '').slice(0,44))}</div>`).join('')
        || '<div class="log">no logins</div>';
      return `<details class="res" data-id="${esc(r.id)}"><summary>
        <b>${esc(r.username)}</b><span class="muted">${esc(r.credits ?? 0)} cr · ${rk.length} keys</span>
        ${r.banned ? '<span class="pill dead">banned</span>' : '<span class="pill live">active</span>'}</summary>
        <div class="body">
        <div class="row" style="margin-bottom:12px">
          <input type="number" step="0.5" value="0" data-add style="width:90px;margin:0">
          <button data-act="add" class="sm">Add credits</button>
          <input type="number" step="0.5" value="${esc(r.credits ?? 0)}" data-set style="width:90px;margin:0">
          <button data-act="set" class="sm">Set credits</button>
          <button data-act="pw" class="sm">Reset password</button>
          <button data-act="ban" class="sm">${r.banned ? 'Unban' : 'Ban'}</button>
          <button data-act="del" class="sm danger">Delete</button></div>
        <h2 style="font-size:12px;margin:0 0 8px">Keys</h2>
        ${rk.length ? `<table><thead><tr><th>Key</th><th>Plan</th><th>Expiry</th><th></th></tr></thead><tbody>
          ${rk.map(k => `<tr><td><code>${esc(k.key)}</code></td><td>${esc(k.plan)}</td>
          <td>${esc(countdown(k.expiresAt))}</td>
          <td>${k.revoked ? '<span class="pill dead">revoked</span>'
            : `<button data-act="revoke" data-key="${esc(k.key)}" class="sm">Revoke</button>`}</td></tr>`).join('')}
        </tbody></table>` : '<p class="muted" style="margin:0">none</p>'}
        <h2 style="font-size:12px;margin:14px 0 6px">Recent logins</h2>${lg}</div></details>`;
    }).join('');
  } catch (err) { toast(err.message, 'err'); }
}

async function onAdminAction(e) {
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const row = btn.closest('.res'), id = row.dataset.id, act = btn.dataset.act,
    token = localStorage.getItem(LS.token) || CFG.SHARED_TOKEN;
  btn.disabled = true;
  try {
    if (act === 'add') {
      const n = Number(row.querySelector('[data-add]').value || 0);
      if (!n) throw new Error('Enter an amount.');
      await mutateResellers(d => {
        const r = d.resellers.find(x => x.id === id);
        if (r) r.credits = +((r.credits ?? 0) + n).toFixed(2);
      }, token, 'add credits');
    } else if (act === 'set') {
      const n = Math.max(0, Number(row.querySelector('[data-set]').value || 0));
      await mutateResellers(d => {
        const r = d.resellers.find(x => x.id === id); if (r) r.credits = +n.toFixed(2);
      }, token, 'set credits');
    } else if (act === 'pw') {
      const pw = prompt('New password (8+ chars):'); if (!pw) return;
      if (pw.length < 8) throw new Error('Too short.');
      const h = await hashPassword(pw);
      await mutateResellers(d => {
        const r = d.resellers.find(x => x.id === id); if (r) r.password = h;
      }, token, 'reset password');
      toast('Password reset.', 'ok');
    } else if (act === 'ban') {
      await mutateResellers(d => {
        const r = d.resellers.find(x => x.id === id); if (r) r.banned = !r.banned;
      }, token, 'toggle ban');
    } else if (act === 'del') {
      if (!confirm('Delete this reseller? Keys stay.')) return;
      await mutateResellers(d => { d.resellers = d.resellers.filter(x => x.id !== id); }, token, 'delete reseller');
      toast('Deleted.', 'ok');
    } else if (act === 'revoke') {
      const key = btn.dataset.key;
      if (!confirm('Revoke ' + key + '?')) return;
      await withRetry(async () => {
        const { data, sha } = await loadKeys(token);
        data.keys = (data.keys || []).filter(k => k.key !== key);
        await writeJson(CFG.KEYS_REPO, CFG.KEYS_PATH, data, sha, `revoke ${key}`, token);
      });
      await mutateResellers(d => {
        const r = d.resellers.find(x => x.id === id);
        const k = (r?.keys || []).find(x => x.key === key); if (k) k.revoked = true;
      }, token, 'mark revoked');
      toast('Revoked.', 'ok');
    }
    refreshAdmin();
  } catch (err) { toast(err.message, 'err'); }
  finally { btn.disabled = false; }
}

/* ---------- ticker ---------- */
let ticker = null;
function startTicker() {
  clearInterval(ticker);
  ticker = setInterval(() => {
    $$('[data-exp]').forEach(el => {
      const i = el.dataset.exp; if (!i) return;
      el.textContent = countdown(i);
      el.className = 'pill ' + (new Date(i) > new Date() ? 'live' : 'dead');
    });
  }, 1000);
}
setInterval(() => {
  if (IS_ADMIN && $('#adminConsole') && !$('#adminConsole').classList.contains('hide')) refreshAdmin();
  else if (!IS_ADMIN && currentRecord) reloadRecord().then(r => r && refreshMine()).catch(() => {});
}, 20000);

/* ---------- boot ---------- */
(function boot() {
  if (window.__booted) { dbg('boot skipped (already ran)'); return; }
  window.__booted = true;

  const owner = isAdmin();
  if (owner) $('#navAdmin')?.classList.remove('hide');

  const a = $(`[data-nav="${IS_ADMIN ? 'admin' : 'reseller'}"]`);
  if (a) a.classList.add('active');

  app.innerHTML = IS_ADMIN ? viewAdmin() : viewReseller();

  if (IS_ADMIN) {
    wireAdmin();
    if (owner) openConsole();
    window.__ready = true;
    dbg('ready (admin route)');
    return;
  }

  wireReseller();
  show($('#authPanel'), true);   // login form is ALWAYS the default surface on "/"

  const s = getSession();
  if (s) {
    loadResellers(writeToken(null)).then(({ data }) => {
      const r = (data.resellers || []).find(x => x.id === s.id);
      if (!r) { clearSession(); dbg('session id not found, cleared'); return; }
      if (r.banned) { clearSession(); toast('Account banned.', 'err'); return; }
      openPanel(r);
    }).catch(err => { dbg('session restore failed: ' + err.message); toast(err.message, 'err'); });
  } else if (owner) {
    show($('#ownerNotice'), true);
    dbg('owner flag set — banner shown above login form');
  }

  window.__ready = true;
  dbg('ready (reseller route)');
})();
