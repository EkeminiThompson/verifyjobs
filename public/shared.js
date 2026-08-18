/* ============================================================
   VerifyJobs.org — Shared JavaScript
   Included on every page via <script src="/shared.js" defer></script>
   ============================================================ */

// ── Engine status chip ──────────────────────────────────────
// Polls /health and updates #engineChip / #engineStatus on any page that has them.
(function pollEngine() {
  var chip = document.getElementById('engineChip');
  var el   = document.getElementById('engineStatus');
  if (!el) return;

  function set(cls, text) {
    el.textContent = text;
    if (chip) {
      chip.classList.remove('is-offline', 'is-checking');
      if (cls) chip.classList.add(cls);
    }
  }

  function check() {
    set('is-checking', '● checking');
    var ctrl = new AbortController();
    var t = setTimeout(function () { ctrl.abort(); }, 4000);
    fetch('/health', { signal: ctrl.signal, cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json().catch(function () { return {}; }) : Promise.reject(); })
      .then(function ()  { clearTimeout(t); set('', '● online'); })
      .catch(function () { clearTimeout(t); set('is-offline', '● offline'); });
  }

  check();
  setInterval(check, 60000);
})();

// ── Hamburger / mobile nav ──────────────────────────────────
(function () {
  var btn  = document.getElementById('navHamburger');
  var menu = document.getElementById('mobileMenu');
  if (!btn || !menu) return;

  function openMenu() {
    menu.classList.add('open');
    btn.setAttribute('aria-expanded', 'true');
  }
  function closeMenu() {
    menu.classList.remove('open');
    btn.setAttribute('aria-expanded', 'false');
  }
  function isOpen() {
    return menu.classList.contains('open');
  }

  btn.addEventListener('click', function (e) {
    e.stopPropagation();
    isOpen() ? closeMenu() : openMenu();
  });

  // Close when clicking outside
  document.addEventListener('click', function (e) {
    if (isOpen() && !menu.contains(e.target) && !btn.contains(e.target)) {
      closeMenu();
    }
  });

  // Close on Escape key
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && isOpen()) closeMenu();
  });

  // Close when a menu link is tapped
  menu.querySelectorAll('a').forEach(function (a) {
    a.addEventListener('click', closeMenu);
  });
})();