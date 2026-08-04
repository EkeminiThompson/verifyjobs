(function () {
    'use strict';
    if (window._loaderInjected) return;
    window._loaderInjected = true;

    var CACHE_KEY = 'vj_v3_';
    var CACHE_TTL = 3600000;

    function getCache(k) {
        try {
            var r = sessionStorage.getItem(CACHE_KEY + k);
            if (!r) return null;
            var o = JSON.parse(r);
            return (Date.now() - o.ts < CACHE_TTL) ? o.html : null;
        } catch(e) { return null; }
    }
    function setCache(k, html) {
        try { sessionStorage.setItem(CACHE_KEY + k, JSON.stringify({html:html,ts:Date.now()})); } catch(e) {}
    }

    function getCurrentPath() {
        return window.location.pathname.replace(/\/$/, '').replace(/\/index\.html$/, '') || '/';
    }

    function setActiveLink(nav) {
        var current = getCurrentPath();
        nav.querySelectorAll('a[href]').forEach(function(a) {
            var href = a.getAttribute('href').replace(/\/$/, '').replace(/\/index\.html$/, '') || '/';
            a.classList.toggle('active', href === current);
        });
    }

    function wireHamburger(nav) {
        var toggle = nav.querySelector('#navToggle');
        var dropdown = nav.querySelector('#navDropdown');
        if (!toggle || !dropdown) return;
        var fresh = toggle.cloneNode(true);
        toggle.parentNode.replaceChild(fresh, toggle);
        toggle = fresh;

        function close() {
            dropdown.classList.remove('open');
            toggle.setAttribute('aria-expanded','false');
            toggle.setAttribute('aria-label','Open navigation menu');
        }
        toggle.addEventListener('click', function(e) {
            e.preventDefault(); e.stopPropagation();
            var open = dropdown.classList.contains('open');
            if (open) { close(); } else {
                dropdown.classList.add('open');
                toggle.setAttribute('aria-expanded','true');
                toggle.setAttribute('aria-label','Close navigation menu');
            }
        });
        dropdown.querySelectorAll('.nav-link').forEach(function(l){ l.addEventListener('click', close); });
        document.addEventListener('click', function(e) {
            if (!toggle.contains(e.target) && !dropdown.contains(e.target)) close();
        });
        document.addEventListener('keydown', function(e) {
            if (e.key==='Escape' && dropdown.classList.contains('open')) { close(); toggle.focus(); }
        });
    }

    function injectPartial(el, url, onDone) {
        if (!el) return;
        // Already has real content — just re-wire
        if (el.querySelector('nav') || el.querySelector('footer')) {
            if (onDone) onDone(el);
            return;
        }

        var cached = getCache(url);
        if (cached) {
            // Synchronous path: inject from cache with no async gap
            var frag = document.createRange().createContextualFragment(cached);
            el.appendChild(frag);
            if (onDone) onDone(el);
            return;
        }

        // Network fetch (first load only)
        fetch(url, {cache:'default'})
            .then(function(r){ return r.ok ? r.text() : Promise.reject(r.status); })
            .then(function(html){
                setCache(url, html);
                var frag = document.createRange().createContextualFragment(html);
                el.appendChild(frag);
                if (onDone) onDone(el);
            })
            .catch(function(e){ console.warn('[loader]', url, e); });
    }

    function init() {
        var headerEl = document.getElementById('site-header');
        var footerEl = document.getElementById('site-footer');

        injectPartial(headerEl, '/partials/header.html', function(el) {
            var nav = el.querySelector('nav');
            if (nav) { setActiveLink(nav); wireHamburger(nav); }
        });

        injectPartial(footerEl, '/partials/footer.html', null);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    window.addEventListener('pageshow', function(e) {
        if (!e.persisted) return;
        var headerEl = document.getElementById('site-header');
        if (headerEl) {
            var nav = headerEl.querySelector('nav');
            if (nav) { setActiveLink(nav); wireHamburger(nav); }
        }
    });
})();