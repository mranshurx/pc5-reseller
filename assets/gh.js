/* GitHub Contents API wrapper (browser / CORS) */
window.PC5GH = (function () {
  var API = 'https://api.github.com';

  function utf8ToB64(s) { return btoa(unescape(encodeURIComponent(s))); }
  function b64ToUtf8(b) { return decodeURIComponent(escape(atob(String(b).replace(/\s+/g, '')))); }

  function headers(token) {
    var o = { 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
    if (token) o['Authorization'] = 'Bearer ' + token;
    return o;
  }

  function fail(r) {
    return r.json().catch(function () { return {}; }).then(function (j) {
      var e = new Error(j.message || ('GitHub error ' + r.status));
      e.status = r.status;
      throw e;
    });
  }

  function getFile(repo, path, branch, token) {
    var url = API + '/repos/' + repo + '/contents/' + path +
      (branch ? '?ref=' + encodeURIComponent(branch) : '');
    return fetch(url, { headers: headers(token), cache: 'no-store' }).then(function (r) {
      if (r.status === 404) return null;
      if (!r.ok) return fail(r);
      return r.json().then(function (j) {
        return { content: b64ToUtf8(j.content || ''), sha: j.sha };
      });
    });
  }

  function putFile(repo, path, branch, token, content, sha, message) {
    if (!token) return Promise.reject(new Error('A GitHub token is required to write.'));
    var body = { message: message || 'update', content: utf8ToB64(content) };
    if (branch) body.branch = branch;
    if (sha) body.sha = sha;
    return fetch(API + '/repos/' + repo + '/contents/' + path, {
      method: 'PUT',
      headers: Object.assign(headers(token), { 'Content-Type': 'application/json' }),
      body: JSON.stringify(body)
    }).then(function (r) { return r.ok ? r.json() : fail(r); });
  }

  function rawRead(repo, path, branch) {
    return fetch('https://raw.githubusercontent.com/' + repo + '/' + branch + '/' + path +
      '?t=' + Date.now(), { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.text() : null; });
  }

  function whoAmI(token) {
    return fetch(API + '/user', { headers: headers(token) })
      .then(function (r) { return r.ok ? r.json() : fail(r); });
  }

  return { getFile: getFile, putFile: putFile, rawRead: rawRead, whoAmI: whoAmI };
})();
