(function () {
  'use strict';

  var CFG = window.PC5_CONFIG;
  var GH = window.PC5GH;

  /* ---------------- dom helpers ---------------- */
  function $(s, r) { return (r || document).querySelector(s); }
  function h(tag, attrs) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined) return;
      if (k === 'class') n.className = v;
      else if (k === 'html') n.innerHTML = v;
      else if (k === 'text') n.textContent = v;
      else if (k.slice(0, 2) === 'on') n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    });
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c === null || c === undefined || c === false) continue;
      if (Array.isArray(c)) c.forEach(function (x) {
        if (x !== null && x !== undefined) n.appendChild(typeof x === 'string' ? document.createTextNode(x) : x);
      });
      else n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return n;
  }

  /* ---------------- misc ---------------- */
  function nowISO() { return new Date().toISOString(); }
  function addHours(hours) { return new Date(Date.now() + hours * 3600000).toISOString(); }
  function fmtCredits(n) { return (Math.round(Number(n) * 100) / 100).toString(); }
  function fmtDate(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleString(undefined, {
      year: '2-digit', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit'
    });
  }
  function ago(iso) {
    if (!iso) return 'never';
    var s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 0) return 'now';
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }
  function remain(iso) {
    if (!iso) return '—';
    var ms = new Date(iso).getTime() - Date.now();
    if (ms <= 0) {
      var past = Math.floor(-ms / 1000);
      if (past < 60) return 'expired';
      if (past < 3600) return 'expired ' + Math.floor(past / 60) + 'm ago';
      if (past < 86400) return 'expired ' + Math.floor(past / 3600) + 'h ago';
      return 'expired ' + Math.floor(past / 86400) + 'd ago';
    }
    var s = Math.floor(ms / 1000);
    var d = Math.floor(s / 86400); s %= 86400;
    var hh = Math.floor(s / 3600); s %= 3600;
    var m = Math.floor(s / 60); s %= 60;
    if (d) return d + 'd ' + hh + 'h left';
    if (hh) return hh + 'h ' + m + 'm left';
    if (m) return m + 'm ' + s + 's left';
    return s + 's left';
  }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function randHex(bytes) {
    var a = new Uint8Array(bytes);
    crypto.getRandomValues(a);
    return Array.from(a).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  /* PC5-XXXXXX from the configured alphabet */
  function genKey() {
    var a = new Uint8Array(CFG.KEY_LEN);
    crypto.getRandomValues(a);
    var out = '';
    for (var i = 0; i < a.length; i++) out += CFG.KEY_ALPHABET[a[i] % CFG.KEY_ALPHABET.length];
    return CFG.KEY_PREFIX + out;
  }

  function planByHours(hr) {
    for (var i = 0; i < CFG.PLANS.length; i++) if (CFG.PLANS[i].hours === hr) return CFG.PLANS[i];
    return null;
  }
  function stateOf(k) {
    if (k.revoked) return { c: 'rev', t: 'Revoked' };
    if (!k.startedAt) return { c: 'idle', t: 'Not started' };
    if (k.expiresAt && new Date(k.expiresAt).getTime() <= Date.now()) return { c: 'dead', t: 'Expired' };
    return { c: 'live', t: 'Active' };
  }

  /* ---------------- hashing ---------------- */
  function hexToBytes(hex) {
    var a = new Uint8Array(hex.length / 2);
    for (var i = 0; i < a.length; i++) a[i] = parseInt(hex.substr(i * 2, 2), 16);
    return a;
  }
  function bytesToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }
  function sha256Fallback(str) {
    function rr(v, n) { return (v >>> n) | (v << (32 - n)); }
    var K = [], H = [], primes = [], n = 2, i;
    while (primes.length < 64) {
      var isP = true;
      for (var d = 2; d * d <= n; d++) if (n % d === 0) { isP = false; break; }
      if (isP) primes.push(n);
      n++;
    }
    for (i = 0; i < 64; i++) K[i] = (Math.pow(primes[i], 1 / 3) % 1 * 4294967296) | 0;
    for (i = 0; i < 8; i++) H[i] = (Math.pow(primes[i], 1 / 2) % 1 * 4294967296) | 0;
    var bytes = new TextEncoder().encode(str);
    var bitLen = bytes.length * 8;
    var padded = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
    padded.set(bytes); padded[bytes.length] = 0x80;
    for (i = 0; i < 8; i++) padded[padded.length - 1 - i] = (bitLen >>> (8 * i)) & 0xff;
    for (var off = 0; off < padded.length; off += 64) {
      var w = [];
      for (i = 0; i < 16; i++) w[i] = (padded[off + i * 4] << 24) | (padded[off + i * 4 + 1] << 16) | (padded[off + i * 4 + 2] << 8) | padded[off + i * 4 + 3];
      for (i = 16; i < 64; i++) {
        var s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      var a = H[0], b = H[1], c = H[2], dd = H[3], e = H[4], f = H[5], g = H[6], hh = H[7];
      for (i = 0; i < 64; i++) {
        var S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K[i] + w[i]) | 0;
        var S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) | 0;
        hh = g; g = f; f = e; e = (dd + t1) | 0;
        dd = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + dd) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + hh) | 0;
    }
    var out = '';
    for (i = 0; i < 8; i++) out += (H[i] >>> 0).toString(16).padStart(8, '0');
    return out;
  }
  async function hashPass(pass, saltHex) {
    if (!(window.crypto && crypto.subtle && crypto.subtle.importKey)) {
      var acc = saltHex + ':' + pass;
      for (var i = 0; i < 5000; i++) acc = sha256Fallback(acc + ':' + i);
      return 'fb$' + acc;
    }
    var key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: 120000, hash: 'SHA-256' }, key, 256);
    return bytesToHex(bits);
  }

  /* ---------------- state ---------------- */
  var S = {
    view: 'reseller',
    busy: false,
    me: null,
    data: { resellers: [] },
    admin: false,
    adminToken: localStorage.getItem('pc5_admin_token') || '',
    expanded: {},
    activateOnCreate: CFG.ACTIVATE_ON_CREATE
  };
  var SESSION_KEY = 'pc5_session';

  function toast(msg, kind) {
    var t = h('div', { class: 'toast ' + (kind || ''), text: msg });
    $('#toasts').appendChild(t);
    setTimeout(function () { t.classList.add('out'); }, 3200);
    setTimeout(function () { t.remove(); }, 3800);
  }
  function setBusy(v) { S.busy = v; document.body.classList.toggle('busy', v); }

  /* ---------------- storage layer ---------------- */
  function writerToken() { return (S.me && S.me.ghToken) || S.adminToken || CFG.SHARED_TOKEN || ''; }

  async function loadResellers() {
    var res = null;
    if (S.adminToken) {
      try {
        var f = await GH.getFile(CFG.DATA_REPO, CFG.DATA_FILE, CFG.DATA_BRANCH, S.adminToken);
        res = f ? JSON.parse(f.content) : null;
      } catch (e) { res = null; }
    }
    if (!res) {
      var raw = await GH.rawRead(CFG.DATA_REPO, CFG.DATA_FILE, CFG.DATA_BRANCH);
      res = raw ? JSON.parse(raw) : null;
    }
    if (!res || !Array.isArray(res.resellers)) res = { resellers: [] };
    S.data = res;
    return res;
  }

  async function saveResellers(mutator, token) {
    var tok = token || writerToken();
    if (!tok) throw new Error('No write token available.');
    for (var attempt = 0; attempt < 4; attempt++) {
      var f = await GH.getFile(CFG.DATA_REPO, CFG.DATA_FILE, CFG.DATA_BRANCH, tok);
      var data = f && f.content ? JSON.parse(f.content) : { resellers: [] };
      if (!Array.isArray(data.resellers)) data.resellers = [];
      mutator(data);
      try {
        await GH.putFile(CFG.DATA_REPO, CFG.DATA_FILE, CFG.DATA_BRANCH, tok,
          JSON.stringify(data, null, 2), f ? f.sha : null, 'reseller: update');
        S.data = data;
        return data;
      } catch (e) {
        if (e.status !== 409 && e.status !== 422) throw e;
        await sleep(400 * (attempt + 1));
      }
    }
    throw new Error('Write conflict, retry.');
  }

  async function saveKeys(mutator, token) {
    if (!token) throw new Error('Add your GitHub token first.');
    for (var attempt = 0; attempt < 4; attempt++) {
      var f = await GH.getFile(CFG.KEYS_REPO, CFG.KEYS_FILE, CFG.KEYS_BRANCH, token);
      var db = f && f.content ? JSON.parse(f.content)
        : { keys: [], maintenance: { enabled: false, message: '' } };
      if (!Array.isArray(db.keys)) db.keys = [];
      if (!db.maintenance) db.maintenance = { enabled: false, message: '' };
      mutator(db);
      try {
        await GH.putFile(CFG.KEYS_REPO, CFG.KEYS_FILE, CFG.KEYS_BRANCH, token,
          JSON.stringify(db, null, 2), f ? f.sha : null, 'keys: issue via reseller panel');
        return db;
      } catch (e) {
        if (e.status !== 409 && e.status !== 422) throw e;
        await sleep(400 * (attempt + 1));
      }
    }
    throw new Error('Write conflict, retry.');
  }

  function findMe() {
    var s = JSON.parse(localStorage.getItem(SESSION_KEY) || 'null');
    if (!s) return null;
    return S.data.resellers.find(function (r) { return r.id === s.id; }) || null;
  }

  /* ---------------- router ---------------- */
  function route() {
    var sig = (location.pathname + location.search + location.hash).toLowerCase();
    var isAdmin = /\/vips(\/|$|\?|#)/.test(sig) || /[?&]p=vips/.test(sig) || /#vips/.test(sig);
    S.view = isAdmin ? 'admin' : 'reseller';
    render();
  }

  /* ---------------- reseller auth ---------------- */
  async function doRegister(ev) {
    ev.preventDefault();
    var username = $('#r-user').value.trim().toLowerCase();
    var pass = $('#r-pass').value;
    var pass2 = $('#r-pass2').value;
    var ghTok = $('#r-token').value.trim();

    if (!/^[a-z0-9_-]{3,24}$/.test(username)) return toast('Username: 3-24 chars, a-z 0-9 _ -', 'err');
    if (pass.length < 6) return toast('Password needs 6+ characters', 'err');
    if (pass !== pass2) return toast('Passwords do not match', 'err');

    var writer = ghTok || CFG.SHARED_TOKEN;
    if (!writer) return toast('Registration closed: no write token configured.', 'err');

    setBusy(true);
    try {
      var salt = randHex(16);
      var rec = {
        id: 'R-' + randHex(5), username: username, salt: salt,
        passHash: await hashPass(pass, salt), credits: 0,
        createdAt: nowISO(), lastLogin: null, lastSeen: null,
        ghToken: ghTok, status: 'active', logins: [], keys: []
      };
      await saveResellers(function (d) {
        if (d.resellers.some(function (x) { return x.username === username; })) {
          throw new Error('Username already taken');
        }
        d.resellers.push(rec);
      }, writer);
      localStorage.setItem(SESSION_KEY, JSON.stringify({ id: rec.id }));
      S.me = rec;
      toast('Account created — ask the owner for credits.', 'ok');
      render();
    } catch (e) { toast(e.message, 'err'); }
    finally { setBusy(false); }
  }

  async function doLogin(ev) {
    ev.preventDefault();
    var username = $('#l-user').value.trim().toLowerCase();
    var pass = $('#l-pass').value;
    if (!username || !pass) return toast('Fill both fields', 'err');
    setBusy(true);
    try {
      await loadResellers();
      var rec = S.data.resellers.find(function (r) { return r.username === username; });
      if (!rec) return toast('No such reseller', 'err');
      if (rec.status === 'banned') return toast('Account banned', 'err');
      if (await hashPass(pass, rec.salt) !== rec.passHash) return toast('Wrong password', 'err');

      var ip = '';
      try {
        var r = await Promise.race([
          fetch('https://api.ipify.org?format=json').then(function (x) { return x.json(); }),
          sleep(3000).then(function () { return null; })
        ]);
        ip = (r && r.ip) || '';
      } catch (e) { ip = ''; }

      await saveResellers(function (d) {
        var t = d.resellers.find(function (x) { return x.id === rec.id; });
        if (!t) return;
        t.lastLogin = nowISO();
        t.lastSeen = nowISO();
        t.logins = (t.logins || []).slice(0, 49);
        t.logins.unshift({ at: nowISO(), ip: ip, ua: navigator.userAgent.slice(0, 180) });
      }, rec.ghToken || CFG.SHARED_TOKEN || S.adminToken);

      localStorage.setItem(SESSION_KEY, JSON.stringify({ id: rec.id }));
      S.me = S.data.resellers.find(function (x) { return x.id === rec.id; });
      toast('Welcome back, ' + rec.username, 'ok');
      render();
    } catch (e) { toast(e.message, 'err'); }
    finally { setBusy(false); }
  }

  function logout() {
    localStorage.removeItem(SESSION_KEY);
    S.me = null;
    render();
  }

  /* ---------------- reseller actions ---------------- */
  async function saveMyToken(ev) {
    ev.preventDefault();
    var tok = $('#tk').value.trim();
    if (!tok) return toast('Paste a token', 'err');
    setBusy(true);
    try {
      var who = await GH.whoAmI(tok);
      await saveResellers(function (d) {
        var t = d.resellers.find(function (x) { return x.id === S.me.id; });
        if (t) t.ghToken = tok;
      }, tok);
      S.me.ghToken = tok;
      toast('Token saved for ' + who.login, 'ok');
      render();
    } catch (e) { toast('Token rejected: ' + e.message, 'err'); }
    finally { setBusy(false); }
  }

  /* mint a key: write into keys.json with full expiry timestamps */
  async function issueKey(plan, unlimited) {
    if (S.busy || !S.me) return;
    var tok = S.me.ghToken;
    if (!tok) return toast('Add your GitHub token first', 'err');
    if (S.me.status === 'banned') return toast('Account banned', 'err');
    if (Number(S.me.credits) < plan.credits) return toast('Not enough credits', 'err');

    setBusy(true);
    var made = null;
    try {
      await saveKeys(function (db) {
        var k, guard = 0;
        do { k = genKey(); guard++; }
        while (db.keys.some(function (x) { return x.key === k; }) && guard < 40);

        var created = nowISO();
        var start = S.activateOnCreate ? created : null;
        var rec = {
          key: k,
          durationHours: plan.hours,
          maxDevices: unlimited ? 0 : 1,
          deviceLimit: unlimited ? 'unlimited' : 'single',
          devices: [],
          createdAt: created,
          startedAt: start,
          activatedAt: start,
          expiresAt: start ? addHours(plan.hours) : null
        };
        db.keys.unshift(rec);
        made = rec;
      }, tok);

      await saveResellers(function (d) {
        var t = d.resellers.find(function (x) { return x.id === S.me.id; });
        if (!t) return;
        t.credits = Math.max(0, Math.round((Number(t.credits) - plan.credits) * 100) / 100);
        t.keys = t.keys || [];
        t.keys.unshift({
          key: made.key, durationHours: plan.hours, credits: plan.credits,
          unlimited: !!unlimited, createdAt: made.createdAt,
          startedAt: made.startedAt, expiresAt: made.expiresAt, revoked: false
        });
      }, tok);

      S.me = S.data.resellers.find(function (x) { return x.id === S.me.id; });
      toast('Key minted: ' + made.key, 'ok');
      render();
    } catch (e) {
      toast(e.message, 'err');
    } finally { setBusy(false); }
  }

  function copy(text) {
    navigator.clipboard.writeText(text).then(
      function () { toast('Copied', 'ok'); },
      function () { toast('Copy failed', 'err'); }
    );
  }

  /* ---------------- admin ---------------- */
  function adminLogin(ev) {
    ev.preventDefault();
    if ($('#ap').value !== CFG.ADMIN_PASSWORD) return toast('Wrong admin password', 'err');
    S.admin = true;
    localStorage.setItem('pc5_admin', '1');
    render();
    refreshAdmin();
  }

  function adminLogout() {
    S.admin = false;
    localStorage.removeItem('pc5_admin');
    render();
  }

  async function saveAdminToken(ev) {
    ev.preventDefault();
    var tok = $('#atk').value.trim();
    if (!tok) return;
    setBusy(true);
    try {
      var who = await GH.whoAmI(tok);
      S.adminToken = tok;
      localStorage.setItem('pc5_admin_token', tok);
      toast('Admin token set (' + who.login + ')', 'ok');
      render();
      refreshAdmin();
    } catch (e) { toast('Token rejected: ' + e.message, 'err'); }
    finally { setBusy(false); }
  }

  function clearAdminToken() {
    S.adminToken = '';
    localStorage.removeItem('pc5_admin_token');
    render();
  }

  async function refreshAdmin() {
    if (!S.admin) return;
    try {
      await loadResellers();
      if (S.admin) render();
    } catch (e) { toast('Load failed: ' + e.message, 'err'); }
  }

  async function addCredits(id, mode) {
    var val = parseFloat($('#cr-' + id).value);
    if (isNaN(val)) return toast('Enter a number', 'err');
    if (!S.adminToken && !CFG.SHARED_TOKEN) return toast('Set an admin token first', 'err');
    setBusy(true);
    try {
      await saveResellers(function (d) {
        var t = d.resellers.find(function (x) { return x.id === id; });
        if (!t) return;
        var base = Number(t.credits) || 0;
        var next = mode === 'set' ? val : base + val;
        t.credits = Math.max(0, Math.round(next * 100) / 100);
      });
      toast('Credits updated', 'ok');
      render();
    } catch (e) { toast(e.message, 'err'); }
    finally { setBusy(false); }
  }

  async function toggleBan(id) {
    setBusy(true);
    try {
      await saveResellers(function (d) {
        var t = d.resellers.find(function (x) { return x.id === id; });
        if (t) t.status = t.status === 'banned' ? 'active' : 'banned';
      });
      render();
    } catch (e) { toast(e.message, 'err'); }
    finally { setBusy(false); }
  }

  async function resetPass(id) {
    var np = prompt('New password (6+ chars):');
    if (!np || np.length < 6) return toast('Cancelled or too short', 'err');
    setBusy(true);
    try {
      var salt = randHex(16);
      var hash = await hashPass(np, salt);
      await saveResellers(function (d) {
        var t = d.resellers.find(function (x) { return x.id === id; });
        if (t) { t.salt = salt; t.passHash = hash; }
      });
      toast('Password reset', 'ok');
    } catch (e) { toast(e.message, 'err'); }
    finally { setBusy(false); }
  }

  async function deleteReseller(id, username) {
    if (!confirm('Delete reseller "' + username + '"? Key log is removed too.')) return;
    setBusy(true);
    try {
      await saveResellers(function (d) {
        d.resellers = d.resellers.filter(function (x) { return x.id !== id; });
      });
      toast('Reseller deleted', 'ok');
      render();
    } catch (e) { toast(e.message, 'err'); }
    finally { setBusy(false); }
  }

  /* kill a key: remove it from keys.json and flag the record */
  async function revokeKey(ownerId, key) {
    var tok = S.adminToken || CFG.SHARED_TOKEN;
    if (!tok) return toast('Set an admin token first', 'err');
    if (!confirm('Revoke ' + key + '? It is deleted from the license database.')) return;
    setBusy(true);
    try {
      await saveKeys(function (db) {
        db.keys = db.keys.filter(function (x) { return x.key !== key; });
      }, tok);
      await saveResellers(function (d) {
        var t = d.resellers.find(function (x) { return x.id === ownerId; });
        if (!t) return;
        (t.keys || []).forEach(function (k) { if (k.key === key) k.revoked = true; });
      }, tok);
      toast('Key revoked', 'ok');
      render();
    } catch (e) { toast(e.message, 'err'); }
    finally { setBusy(false); }
  }

  /* ---------------- render ---------------- */
  function render() {
    var app = $('#app');
    app.innerHTML = '';
    $('#nav-reseller').classList.toggle('on', S.view === 'reseller');
    $('#nav-admin').classList.toggle('on', S.view === 'admin');
    if (S.view === 'admin') renderAdmin(app); else renderReseller(app);
    $('#footstat').textContent = S.view === 'admin' ? 'admin console' : 'credits = keys';
    tick();
  }

  function renderReseller(app) {
    if (!S.me) {
      app.appendChild(h('div', { class: 'hero' },
        h('h1', {}, 'PC5 ', h('span', { class: 'grad', text: 'Key Reseller' })),
        h('p', { class: 'sub', text: 'Buy credits, mint license keys, deliver instantly. Keys are written straight into the live license database with a real expiry.' })
      ));

      var grid = h('div', { class: 'authgrid' });

      grid.appendChild(h('form', { class: 'card', onsubmit: doLogin },
        h('h2', { text: 'Sign in' }),
        h('label', { text: 'Username' }),
        h('input', { id: 'l-user', autocomplete: 'username', placeholder: 'your username' }),
        h('label', { text: 'Password' }),
        h('input', { id: 'l-pass', type: 'password', autocomplete: 'current-password', placeholder: '••••••••' }),
        h('button', { class: 'btn primary', type: 'submit', text: 'Sign in' })
      ));

      grid.appendChild(h('form', { class: 'card', onsubmit: doRegister },
        h('h2', { text: 'Create account' }),
        h('label', { text: 'Username' }),
        h('input', { id: 'r-user', autocomplete: 'username', placeholder: '3-24 chars, a-z 0-9 _ -' }),
        h('label', { text: 'Password' }),
        h('input', { id: 'r-pass', type: 'password', autocomplete: 'new-password', placeholder: 'min 6 chars' }),
        h('label', { text: 'Repeat password' }),
        h('input', { id: 'r-pass2', type: 'password', autocomplete: 'new-password' }),
        h('label', {}, 'GitHub token ', h('span', { class: 'hint', text: '(optional now)' })),
        h('input', { id: 'r-token', placeholder: 'github_pat_…' }),
        h('button', { class: 'btn', type: 'submit', text: 'Register' })
      ));

      app.appendChild(grid);
      return;
    }

    var me = S.me;
    app.appendChild(h('div', { class: 'rowhead' },
      h('div', {},
        h('h1', {}, 'Hi, ', h('span', { class: 'grad', text: me.username })),
        h('p', { class: 'sub', text: 'Balance: ' + fmtCredits(me.credits) + ' credits' })
      ),
      h('button', { class: 'btn ghost', onclick: logout, text: 'Sign out' })
    ));

    if (me.status === 'banned') app.appendChild(h('div', { class: 'banner err', text: 'Account banned — contact the owner.' }));

    var tokOk = !!me.ghToken;
    app.appendChild(h('section', { class: 'card' },
      h('div', { class: 'rowhead tight' },
        h('h2', { text: 'GitHub write token' }),
        h('span', { class: 'badge ' + (tokOk ? 'ok' : 'warn'), text: tokOk ? 'connected' : 'required' })
      ),
      h('p', { class: 'sub', text: 'Keys are pushed with your own token. Fine-grained PAT, Contents: Read and write on the license repo only.' }),
      h('form', { class: 'inline', onsubmit: saveMyToken },
        h('input', { id: 'tk', type: 'password', placeholder: tokOk ? '•••••••• (saved — paste to replace)' : 'github_pat_…' }),
        h('button', { class: 'btn', type: 'submit', text: 'Save token' })
      )
    ));

    var bal = Number(me.credits) || 0;
    var planWrap = h('section', { class: 'card' },
      h('div', { class: 'rowhead tight' },
        h('h2', { text: 'Mint a key' }),
        h('div', { class: 'toggles' },
          h('label', { class: 'switch' },
            h('input', {
              type: 'checkbox', ...(S.activateOnCreate ? { checked: 'checked' } : {}),
              onchange: function (e) { S.activateOnCreate = e.target.checked; }
            }),
            h('span', { text: 'start immediately' })
          ),
          h('label', { class: 'switch' },
            h('input', { type: 'checkbox', id: 'unl' }),
            h('span', { text: 'multi-device' })
          )
        )
      ),
      h('p', { class: 'sub', text: 'Expiry is stamped on creation from the plan length. Uncheck "start immediately" to leave the timer for the customer\'s first launch.' })
    );

    var pg = h('div', { class: 'plans' });
    CFG.PLANS.forEach(function (p) {
      var can = bal >= p.credits && !!me.ghToken && me.status !== 'banned';
      pg.appendChild(h('button', {
        class: 'plan' + (can ? '' : ' off'), ...(can ? {} : { disabled: 'disabled' }),
        onclick: function () { issueKey(p, $('#unl') && $('#unl').checked); }
      },
        h('span', { class: 'plabel', text: p.label }),
        h('span', { class: 'pcost', text: fmtCredits(p.credits) + ' cr' })
      ));
    });
    planWrap.appendChild(pg);
    app.appendChild(planWrap);

    /* my keys with live countdown */
    var keys = (me.keys || []).slice();
    var kw = h('section', { class: 'card' },
      h('div', { class: 'rowhead tight' },
        h('h2', { text: 'My keys' }),
        h('span', { class: 'badge', text: keys.length + ' total' })
      )
    );
    if (!keys.length) kw.appendChild(h('p', { class: 'sub', text: 'No keys yet.' }));
    else {
      var tb = h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {},
          h('th', { text: 'Key' }), h('th', { text: 'Plan' }), h('th', { text: 'Created' }),
          h('th', { text: 'Expiry' }), h('th', { text: 'Cost' }), h('th', { text: '' })
        ))
      );
      var body = h('tbody');
      keys.forEach(function (k) {
        var st = stateOf(k);
        body.appendChild(h('tr', {},
          h('td', {}, h('code', { text: k.key }), h('span', { class: 'tag ' + st.c, text: st.t })),
          h('td', { text: (planByHours(k.durationHours) || { label: k.durationHours + 'h' }).label + (k.unlimited ? ' · multi' : '') }),
          h('td', { text: ago(k.createdAt) }),
          h('td', {}, h('span', { class: 'cd', ...(k.expiresAt ? { 'data-exp': k.expiresAt } : {}), text: k.expiresAt ? remain(k.expiresAt) : 'not started' })),
          h('td', { text: fmtCredits(k.credits) }),
          h('td', {}, h('button', { class: 'btn tiny', onclick: function () { copy(k.key); }, text: 'Copy' }))
        ));
      });
      tb.appendChild(body);
      kw.appendChild(h('div', { class: 'scroll' }, tb));
    }
    app.appendChild(kw);
  }

  function renderAdmin(app) {
    if (!S.admin) {
      app.appendChild(h('div', { class: 'hero' },
        h('h1', {}, 'Reseller ', h('span', { class: 'grad', text: 'Console' })),
        h('p', { class: 'sub', text: 'Restricted area.' })
      ));
      app.appendChild(h('form', { class: 'card narrow', onsubmit: adminLogin },
        h('label', { text: 'Admin password' }),
        h('input', { id: 'ap', type: 'password', autocomplete: 'current-password' }),
        h('button', { class: 'btn primary', type: 'submit', text: 'Unlock' })
      ));
      return;
    }

    var rs = S.data.resellers || [];
    var allKeys = 0, liveKeys = 0, creditsOut = 0, active24 = 0;
    var now = Date.now();
    rs.forEach(function (r) {
      (r.keys || []).forEach(function (k) {
        allKeys++;
        if (k.expiresAt && new Date(k.expiresAt).getTime() > now && !k.revoked) liveKeys++;
      });
      creditsOut += Number(r.credits) || 0;
      if (r.lastSeen && now - new Date(r.lastSeen).getTime() < 86400000) active24++;
    });

    app.appendChild(h('div', { class: 'rowhead' },
      h('div', {},
        h('h1', {}, 'Reseller ', h('span', { class: 'grad', text: 'Console' })),
        h('p', { class: 'sub', text: 'Everything that happens on the reseller site.' })
      ),
      h('div', { class: 'rowhead-actions' },
        h('button', { class: 'btn ghost', onclick: refreshAdmin, text: 'Refresh' }),
        h('button', { class: 'btn ghost', onclick: adminLogout, text: 'Lock' })
      )
    ));

    app.appendChild(h('div', { class: 'stats' },
      h('div', { class: 'stat' }, h('b', { text: rs.length }), h('span', { text: 'resellers' })),
      h('div', { class: 'stat' }, h('b', { text: active24 }), h('span', { text: 'active 24h' })),
      h('div', { class: 'stat' }, h('b', { text: allKeys }), h('span', { text: 'keys issued' })),
      h('div', { class: 'stat' }, h('b', { text: liveKeys }), h('span', { text: 'still valid' })),
      h('div', { class: 'stat' }, h('b', { text: fmtCredits(creditsOut) }), h('span', { text: 'credits held' }))
    ));

    app.appendChild(h('section', { class: 'card' },
      h('div', { class: 'rowhead tight' },
        h('h2', { text: 'Owner token' }),
        h('span', { class: 'badge ' + (S.adminToken ? 'ok' : 'warn'), text: S.adminToken ? 'set' : 'missing' })
      ),
      h('p', { class: 'sub', text: 'Used to write reseller data, credits and revocations. Kept in this browser only.' }),
      h('form', { class: 'inline', onsubmit: saveAdminToken },
        h('input', { id: 'atk', type: 'password', placeholder: 'github_pat_…' }),
        h('button', { class: 'btn', type: 'submit', text: 'Save' }),
        h('button', { class: 'btn ghost', type: 'button', onclick: clearAdminToken, text: 'Clear' })
      )
    ));

    var card = h('section', { class: 'card' }, h('h2', { text: 'Registered resellers' }));
    if (!rs.length) card.appendChild(h('p', { class: 'sub', text: 'Nobody registered yet.' }));

    rs.slice().sort(function (a, b) {
      return new Date(b.createdAt || 0) - new Date(a.createdAt || 0);
    }).forEach(function (r) {
      var open = !!S.expanded[r.id];
      var kcount = (r.keys || []).length;
      var lastLog = (r.logins && r.logins[0]) ? r.logins[0] : null;

      card.appendChild(h('div', { class: 'rrow' },
        h('div', { class: 'rmain' },
          h('div', { class: 'rname' },
            h('b', { text: r.username }),
            h('span', { class: 'badge ' + (r.status === 'banned' ? 'err' : 'ok'), text: r.status || 'active' }),
            h('span', { class: 'badge', text: kcount + ' keys' }),
            h('span', { class: 'badge', text: fmtCredits(r.credits) + ' cr' })
          ),
          h('div', { class: 'rmeta' },
            h('span', { text: 'joined ' + ago(r.createdAt) }),
            h('span', { text: '· last login ' + ago(r.lastLogin) }),
            h('span', { text: '· seen ' + ago(r.lastSeen) }),
            lastLog ? h('span', { text: '· ip ' + (lastLog.ip || 'n/a') }) : null
          )
        ),
        h('button', {
          class: 'btn tiny',
          onclick: function () { S.expanded[r.id] = !open; render(); },
          text: open ? 'Hide' : 'Open'
        })
      ));

      if (open) {
        var body = h('div', { class: 'rbody' });

        body.appendChild(h('div', { class: 'ctl' },
          h('input', { id: 'cr-' + r.id, type: 'number', step: '0.5', min: '0', placeholder: 'credits' }),
          h('button', { class: 'btn tiny primary', onclick: function () { addCredits(r.id, 'add'); }, text: 'Add' }),
          h('button', { class: 'btn tiny', onclick: function () { addCredits(r.id, 'set'); }, text: 'Set exact' }),
          h('button', { class: 'btn tiny', onclick: function () { toggleBan(r.id); }, text: r.status === 'banned' ? 'Unban' : 'Ban' }),
          h('button', { class: 'btn tiny', onclick: function () { resetPass(r.id); }, text: 'Reset pass' }),
          h('button', { class: 'btn tiny danger', onclick: function () { deleteReseller(r.id, r.username); }, text: 'Delete' })
        ));

        body.appendChild(h('p', { class: 'sub mono', text: 'token: ' + (r.ghToken ? r.ghToken.slice(0, 12) + '…' + r.ghToken.slice(-4) : 'none') }));

        if (kcount) {
          var kt = h('table', { class: 'tbl' },
            h('thead', {}, h('tr', {},
              h('th', { text: 'Key' }), h('th', { text: 'Plan' }), h('th', { text: 'Cost' }),
              h('th', { text: 'Created' }), h('th', { text: 'Expiry' }), h('th', { text: '' })
            ))
          );
          var ktb = h('tbody');
          r.keys.slice().reverse().forEach(function (k) {
            var st = stateOf(k);
            ktb.appendChild(h('tr', {},
              h('td', {}, h('code', { text: k.key }), h('span', { class: 'tag ' + st.c, text: st.t })),
              h('td', { text: (planByHours(k.durationHours) || { label: k.durationHours + 'h' }).label }),
              h('td', { text: fmtCredits(k.credits) }),
              h('td', { text: ago(k.createdAt) }),
              h('td', {}, h('span', { class: 'cd', ...(k.expiresAt ? { 'data-exp': k.expiresAt } : {}), text: k.expiresAt ? remain(k.expiresAt) : 'not started' })),
              h('td', {}, k.revoked
                ? h('span', { class: 'dim', text: 'revoked' })
                : h('button', { class: 'btn tiny danger', onclick: function () { revokeKey(r.id, k.key); }, text: 'Revoke' }))
            ));
          });
          kt.appendChild(ktb);
          body.appendChild(h('div', { class: 'scroll' }, kt));
        } else body.appendChild(h('p', { class: 'sub', text: 'No keys minted.' }));

        if (r.logins && r.logins.length) {
          var lg = h('div', { class: 'loglist' });
          r.logins.slice(0, 8).forEach(function (l) {
            lg.appendChild(h('div', { class: 'logrow' },
              h('span', { text: fmtDate(l.at) }),
              h('span', { class: 'mono', text: l.ip || 'no-ip' }),
              h('span', { class: 'dim', text: (l.ua || '').slice(0, 60) })
            ));
          });
          body.appendChild(h('h3', { text: 'Recent logins' }));
          body.appendChild(lg);
        }

        card.appendChild(body);
      }
    });
    app.appendChild(card);
  }

  /* ---------------- live countdown ticker ---------------- */
  function tick() {
    document.querySelectorAll('[data-exp]').forEach(function (el) {
      var iso = el.getAttribute('data-exp');
      el.textContent = remain(iso);
      el.classList.toggle('dead', new Date(iso).getTime() <= Date.now());
    });
  }

  /* ---------------- boot ---------------- */
  async function boot() {
    try {
      await loadResellers();
      S.me = findMe();
    } catch (e) { /* offline first paint */ }
    if (localStorage.getItem('pc5_admin') === '1') S.admin = true;
    route();
    setInterval(tick, 1000);
    setInterval(function () {
      if (S.admin) refreshAdmin();
      else if (S.me) {
        loadResellers().then(function () {
          var fresh = S.data.resellers.find(function (x) { return x.id === S.me.id; });
          if (fresh) S.me = fresh;
        }).catch(function () {});
      }
    }, 20000);
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
