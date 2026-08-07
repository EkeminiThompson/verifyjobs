/* ============================================================
   VerifyJobs.org — Shared JavaScript
   Included on every page via <script src="/shared.js" defer></script>
   ============================================================ */

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
