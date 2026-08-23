/* Virtual Airlines — Crew Center interactions
   — Touch + mobile optimised —
*/
(function () {
  "use strict";

  const menuToggle = document.getElementById("menuToggle");
  const sideMenu   = document.getElementById("sideMenu");
  const menuClose  = document.getElementById("menuClose");
  const backdrop   = document.getElementById("menuBackdrop");
  const navLinks   = sideMenu ? sideMenu.querySelectorAll("a[data-nav]") : [];
  const yearEl     = document.getElementById("year");

  if (yearEl) yearEl.textContent = new Date().getFullYear();

  /* ---------------------------------------------------------
     Swap hero main button based on "logged in" flag:
     - Not logged in : APPLY NEW → register.html
     - Logged in     : FLY NEW   → crew.html
     Also bind a click-time fallback so stale href (cache)
     never takes the user to the wrong page.
     --------------------------------------------------------- */
  /* ---------- Mini cookie helper (used for file:// Android fallback) ---------- */
  function _ckGet(k) {
    try {
      if (typeof document === "undefined" || !document.cookie) return null;
      var m = document.cookie.match(new RegExp(
        "(?:^|;\\s*)" + k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=([^;]*)"
      ));
      if (!m) return null;
      try { return decodeURIComponent(m[1]); } catch (e) { return m[1]; }
    } catch (e) { return null; }
  }

  (function updateMainActionButton() {
    const btn = document.getElementById("mainActionBtn");
    function isLogged() {
      var raw = null;
      try { raw = localStorage.getItem("mfva_logged_in"); } catch (e) { /* swallow */ }
      if (raw == null) raw = _ckGet("mfva_logged_in");
      return raw === "1";
    }
    function refresh() {
      const logged = isLogged();
      // Keep the HTML root flag in sync with any sign-out/sign-in that
      // happens while the user stays on the same tab across page loads.
      document.documentElement.setAttribute("data-mfva-logged", logged ? "1" : "0");
      if (logged) {
        if (btn) {
          btn.textContent = "FLY NEW";
          btn.setAttribute("href", "crew.html");
          btn.dataset.target = "crew.html";
        }
      } else {
        if (btn) {
          btn.textContent = "APPLY NEW";
          btn.setAttribute("href", "register.html");
          btn.dataset.target = "register.html";
        }
      }
    }
    refresh();
    // Click-time guard: ignore stale href from cached HTML.
    if (btn) {
      btn.addEventListener("click", function (e) {
        refresh();
        const target = btn.dataset.target || btn.getAttribute("href") || "index.html";
        if (btn.getAttribute("href") !== target) {
          e.preventDefault();
          window.location.href = target;
        }
      });
    }
  })();

  /* ---------------------------------------------------------
     Prevent iOS Safari from accidentally zooming via double-tap
     and cancel the ~350ms legacy click delay on tap targets.
     --------------------------------------------------------- */
  (function killDoubleTapZoom() {
    let lastTouchEnd = 0;
    document.addEventListener(
      "touchend",
      (e) => {
        const now = Date.now();
        if (now - lastTouchEnd <= 300) {
          const t = e.target;
          if (t && typeof t.closest === "function" && t.closest("a, button, .btn, input, textarea, select, label")) {
            e.preventDefault();
          }
        }
        lastTouchEnd = now;
      },
      { passive: false }
    );
  })();

  /* ---------------------------------------------------------
     iOS viewport-fix: 100vh includes the browser chrome there,
     so we keep --dvh in sync for smooth mobile sizing.
     --------------------------------------------------------- */
  (function syncDvh() {
    const set = () => {
      const vh = (window.visualViewport ? window.visualViewport.height : window.innerHeight) * 0.01;
      document.documentElement.style.setProperty("--dvh", vh + "px");
    };
    set();
    window.addEventListener("resize", set, { passive: true });
    window.addEventListener("orientationchange", set, { passive: true });
    if (window.visualViewport) {
      window.visualViewport.addEventListener("resize", set, { passive: true });
      window.visualViewport.addEventListener("scroll", set, { passive: true });
    }
  })();

  /* ---------------------------------------------------------
     Side menu state helpers — lock page scroll when open
     --------------------------------------------------------- */
  let scrollLockY = 0;
  function lockPageScroll() {
    scrollLockY = window.scrollY || window.pageYOffset;
    const html = document.documentElement;
    html.style.position = "fixed";
    html.style.top = -scrollLockY + "px";
    html.style.left = "0";
    html.style.right = "0";
    html.style.width = "100%";
    document.body.style.overflow = "hidden";
  }
  function unlockPageScroll() {
    const html = document.documentElement;
    html.style.position = "";
    html.style.top = "";
    html.style.left = "";
    html.style.right = "";
    html.style.width = "";
    document.body.style.overflow = "";
    if (scrollLockY) window.scrollTo(0, scrollLockY);
  }

  function openMenu() {
    if (!sideMenu || !backdrop || !menuToggle) return;
    sideMenu.classList.add("is-open");
    backdrop.classList.add("is-open");
    sideMenu.setAttribute("aria-hidden", "false");
    backdrop.setAttribute("aria-hidden", "false");
    menuToggle.setAttribute("aria-expanded", "true");
    menuToggle.setAttribute("aria-label", "Close menu");
    lockPageScroll();
  }

  function closeMenu() {
    if (!sideMenu || !backdrop || !menuToggle) return;
    sideMenu.classList.remove("is-open");
    backdrop.classList.remove("is-open");
    sideMenu.setAttribute("aria-hidden", "true");
    backdrop.setAttribute("aria-hidden", "true");
    menuToggle.setAttribute("aria-expanded", "false");
    menuToggle.setAttribute("aria-label", "Open menu");
    unlockPageScroll();
  }

  if (menuToggle) {
    menuToggle.addEventListener("click", (e) => {
      e.preventDefault();
      const isOpen = sideMenu.classList.contains("is-open");
      isOpen ? closeMenu() : openMenu();
    });
    // Mobile: treat touchend as a click to avoid 300ms feel
    menuToggle.addEventListener("touchend", (e) => {
      // Don't double-fire if browser emits click too
      if (e.cancelable) e.preventDefault();
      const isOpen = sideMenu.classList.contains("is-open");
      isOpen ? closeMenu() : openMenu();
    }, { passive: false });
  }

  if (menuClose) menuClose.addEventListener("click", closeMenu);
  if (backdrop)  backdrop.addEventListener("click", closeMenu);

  // Close menu on ESC
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeMenu();
  });

  // Smooth-scroll for top-nav links (Home etc.)
  const topNavLinks = document.querySelectorAll(".primary-nav a[href^=\"#\"]");
  topNavLinks.forEach((link) => {
    link.addEventListener("click", function (e) {
      const href = this.getAttribute("href");
      if (!href || !href.startsWith("#")) return;
      const target = document.querySelector(href);
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  });

  // Close menu when a side-nav link is clicked
  navLinks.forEach((link) => {
    link.addEventListener("click", () => closeMenu());
    link.addEventListener("touchend", function onTap(e) {
      // small touch devices: close right away to feel snappy
      if (e.cancelable) e.preventDefault();
      closeMenu();
      const href = link.getAttribute("href");
      if (href && href.startsWith("#")) {
        const target = document.querySelector(href);
        if (target) {
          setTimeout(() => target.scrollIntoView({ behavior: "smooth", block: "start" }), 180);
        }
      } else if (href) {
        setTimeout(() => { window.location.href = href; }, 180);
      }
    }, { passive: false });
  });

  /* ---------------------------------------------------------
     Swipe gesture support for the side menu on touch devices
     • Swipe from right edge → open
     • Swipe right when open → close
     --------------------------------------------------------- */
  (function swipeSupport() {
    const EDGE = 24;       // px from right edge to start an "open" swipe
    const THRESHOLD = 72;  // px distance to count as a gesture
    let startX = 0, startY = 0, tracking = false, dir = null, moved = false;

    const onStart = (e) => {
      if (!e.touches || e.touches.length !== 1) return;
      const t = e.touches[0];
      startX = t.clientX;
      startY = t.clientY;
      tracking = true;
      dir = null;
      moved = false;
    };

    const onMove = (e) => {
      if (!tracking || !e.touches || e.touches.length !== 1) return;
      const t = e.touches[0];
      const dx = t.clientX - startX;
      const dy = t.clientY - startY;
      if (!dir) {
        if (Math.abs(dx) < 8 && Math.abs(dy) < 8) return;
        dir = Math.abs(dx) > Math.abs(dy) ? "x" : "y";
      }
      if (dir !== "x") { tracking = false; return; }
      moved = true;
      const isOpen = sideMenu && sideMenu.classList.contains("is-open");

      // Live translate when open (user is swiping it closed)
      if (isOpen && dx < 0 && sideMenu) {
        sideMenu.style.transition = "none";
        sideMenu.style.transform = `translateX(${Math.max(-80, dx)}px)`;
      }
    };

    const onEnd = (e) => {
      if (!tracking) return;
      tracking = false;
      if (!sideMenu) return;
      const isOpen = sideMenu.classList.contains("is-open");
      const endX = (e.changedTouches && e.changedTouches[0]) ? e.changedTouches[0].clientX : startX;
      const dx = endX - startX;

      // Restore transition
      sideMenu.style.transition = "";
      sideMenu.style.transform = "";

      if (!moved || dir !== "x") return;

      const w = window.innerWidth || document.documentElement.clientWidth;
      const fromEdge = (w - startX) <= EDGE;

      if (!isOpen && fromEdge && dx < -THRESHOLD * 0.6) {
        // Swipe left from the right edge → open
        openMenu();
      } else if (isOpen && dx > THRESHOLD) {
        // Swipe right when open → close
        closeMenu();
      }
    };

    document.addEventListener("touchstart", onStart, { passive: true });
    document.addEventListener("touchmove", onMove, { passive: true });
    document.addEventListener("touchend", onEnd, { passive: true });
    document.addEventListener("touchcancel", onEnd, { passive: true });
  })();

  /* ---------------------------------------------------------
     Prevent scroll chaining when the side menu hits top/bottom
     (stops the page behind from scrolling unexpectedly on iOS)
     --------------------------------------------------------- */
  if (sideMenu) {
    sideMenu.addEventListener("touchmove", (e) => {
      if (!sideMenu.classList.contains("is-open")) return;
      const el = sideMenu;
      const atTop = el.scrollTop <= 0;
      const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 1;
      if (atTop || atBottom) {
        // Only block when the user's finger is panning vertically into the wall
        if (e.touches && e.touches[0]) {
          // Let's just bounce-pad: allow 1 extra px but kill chaining
          if (atTop) el.scrollTop = 1;
          if (atBottom) el.scrollTop = el.scrollHeight - el.clientHeight - 1;
          if (e.cancelable) e.preventDefault();
        }
      }
    }, { passive: false });
  }

  /* ---------------------------------------------------------
     Subtle topbar shadow adjustment as user scrolls
     --------------------------------------------------------- */
  const topbar = document.querySelector(".topbar");
  if (topbar) {
    const onScroll = () => {
      const y = window.scrollY || window.pageYOffset;
      if (y > 10) {
        topbar.style.boxShadow = "0 2px 0 rgba(0,0,0,.05), 0 10px 28px -16px rgba(0,0,0,.25)";
      } else {
        topbar.style.boxShadow = "";
      }
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("touchmove", onScroll, { passive: true });
    onScroll();
  }

  /* ---------------------------------------------------------
     Environment banner: show "📱 手机直开模式" notice for
     file:// users where localStorage is disabled.
     Duplicated in auth.js for pages that include it; here we
     use a shared DOM id to avoid double banners.
     --------------------------------------------------------- */
  (function envBanner() {
    try {
      if (typeof document === "undefined") return;
      var proto = (location && location.protocol) || "";
      var isFile = (proto === "file:");
      var lsWorks = false;
      try {
        var k = "__mfva_ls_probe__";
        localStorage.setItem(k, "1");
        lsWorks = (localStorage.getItem(k) === "1");
        localStorage.removeItem(k);
      } catch (e) { lsWorks = false; }
      if (!(isFile && !lsWorks)) return; // HTTP + working localStorage = no banner
      if (document.getElementById("mfva-env-banner")) return; // already injected (by auth.js)

      var el = document.createElement("div");
      el.id = "mfva-env-banner";
      el.style.cssText = [
        "position:fixed;top:0;left:0;right:0;z-index:99999;",
        "background:#fff7cd;color:#7c5a00;",
        "font:13px/1.45 system-ui,-apple-system,'Segoe UI',Roboto,Arial,'PingFang SC','Noto Sans SC',sans-serif;",
        "padding:8px 46px 8px 14px;box-shadow:0 2px 0 rgba(0,0,0,.04);",
        "border-bottom:1px solid #f2d76f;"
      ].join("");
      el.innerHTML = '<b style="margin-right:6px;">📱 手机直开模式</b>' +
        '登录状态可跨页保留，但成员数据刷新后会丢失。' +
        '<button id="mfva-env-banner-close" aria-label="关闭" style="' +
        "position:absolute;right:10px;top:50%;transform:translateY(-50%);" +
        "border:0;background:transparent;color:#7c5a00;font-size:18px;line-height:1;" +
        "padding:2px 6px;cursor:pointer;\">×</button>";
      if (document.body && document.body.firstChild) {
        document.body.insertBefore(el, document.body.firstChild);
      } else if (document.body) {
        document.body.appendChild(el);
      }
      // Push topbar down 40px so hamburger stays clickable
      var tb = document.querySelector(".topbar, [class*=topbar]");
      var origTop = null;
      if (tb && !tb.dataset.mfvaBannerPushed) {
        tb.dataset.mfvaBannerPushed = "1";
        origTop = tb.style.top || "0";
        var pt = parseInt(getComputedStyle(tb).top || "0", 10);
        tb.style.top = (isNaN(pt) ? 40 : pt + 40) + "px";
      }
      var c = document.getElementById("mfva-env-banner-close");
      if (c) {
        c.addEventListener("click", function () {
          el.style.display = "none";
          if (tb && tb.dataset.mfvaBannerPushed === "1") { tb.style.top = origTop; }
        });
      }
    } catch (e) { /* banner failure must never crash the page */ }
  })();
})();
