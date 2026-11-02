(function () {
  var p = location.pathname.replace(/\.html$/i, '').replace(/\/+$/, '');
  var admin = /\/vips$/i.test(p) || /[?&]vips\b/.test(location.search);
  document.documentElement.dataset.route = admin ? 'admin' : 'reseller';
  window.addEventListener('error', function (e) {
    var b = document.getElementById('bootErr');
    if (b) { b.hidden = false; b.textContent = 'Script error: ' + e.message; }
  });
})();
