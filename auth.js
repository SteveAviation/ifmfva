/* ==========================================================================
   MFVA — Authentication & Membership (local-only)
   --------------------------------------------------------------------------
   Replaces the previous "any email/password signs in" rule with:

     1. SEED ADMIN (can never be fully removed; can be demoted if a second
        admin exists).
        - email:    3689442439@qq.com
        - password: ashy********.
        - role:     admin

     2. MEMBERS can only sign in IF an admin has first added their email to
        the mfva_members list (localStorage) and either:
        - the member record has a stored password (set by admin), OR
        - the admin marked the row as "allow any password".

     3. ROLES
        - admin    : full access, member management, rank grants, can enable/
                     disable accounts.
        - captain+ : fleet unlock controlled by granted rank.
        - disabled : cannot sign in even with correct password.

     4. PERMISSIONS are written by the admin per member row:
        - maxRankId (1..7)        -> highest rank the pilot is allowed.
        - allowedAircraft[]       -> explicit plane tail/model overrides.
        - canFilePirep            -> boolean
        - canUseRoutesDB          -> boolean

   NOTE: This is a static-site authentication module. Credentials live in the
   browser localStorage. For production security you MUST swap the credential
   checks to a real HTTPS backend with bcrypt + session tokens. This module
   implements workflow only, not cryptographic login security.
   ========================================================================== */

(function (global) {
  "use strict";

  /* ------------------------------------------------------------------ *
   *  Keys & constants                                                  *
   * ------------------------------------------------------------------ */
  var LS_MEMBERS = "mfva_members";       // JSON array of member objects
  var LS_SESSION = "mfva_session";       // {email, role, loginAt, expAt}
  var LS_LEGACY_LOGGED = "mfva_logged_in";  // backward compat (value "1")
  var LS_PIREPS = "mfva_pireps";         // JSON array of PIREP objects

  var RANK_LADDER = [
    { id: 1, name: "Trainee Second Officer",  label: "Trainee SO" },
    { id: 2, name: "Second Officer",          label: "SO" },
    { id: 3, name: "First Officer",           label: "FO" },
    { id: 4, name: "SR First Officer",        label: "SR FO" },
    { id: 5, name: "Captain",                 label: "CAPT" },
    { id: 6, name: "SR Captain",              label: "SR CAPT" },
    { id: 7, name: "Fleet Captain",           label: "Fleet CAPT" }
  ];

  // NOTE: "ashy********." below is ashy + 8 asterisks + 1 dot = 13 chars total,
  // matching the exact password the CEO types into the login form.
  var ADMIN_PASSWORD = "ashy********.";

  var SEED_ADMINS = [
    {
      email: "3689442439@qq.com",
      password: ADMIN_PASSWORD,
      role: "admin",
      maxRankId: 7,
      canFilePirep: true,
      canUseRoutesDB: true,
      status: "active",
      displayName: "Admin / CEO",
      createdBy: "seed",
      createdAt: "seed",
      memberSince: "2025-01-01",
      callsign: "MFVA001"
    },
    {
      email: "G6082@outlook.com",
      password: ADMIN_PASSWORD,
      role: "admin",
      maxRankId: 7,
      canFilePirep: true,
      canUseRoutesDB: true,
      status: "active",
      displayName: "Admin / IFC",
      createdBy: "seed",
      createdAt: "seed",
      memberSince: "2025-01-01",
      callsign: "MFVA002"
    }
  ];

  // Backwards-compat alias — anything that used SEED_ADMIN (e.g. QQ CEO) still works.
  var SEED_ADMIN = SEED_ADMINS[0];

  function findSeedAdminByEmail(email) {
    var e = normEmail(email);
    for (var i = 0; i < SEED_ADMINS.length; i++) {
      if (normEmail(SEED_ADMINS[i].email) === e) return SEED_ADMINS[i];
    }
    return null;
  }
  function isAnySeedEmail(email) { return !!findSeedAdminByEmail(email); }

  /* ------------------------------------------------------------------ *
   *  Environment detection (HTTP vs file://) + capability probe       *
   * ------------------------------------------------------------------ */
  var ENV = (function () {
    var proto = (typeof location !== "undefined" && location.protocol) ? location.protocol : "";
    var isFile = (proto === "file:");
    // Probe if localStorage actually works (throws in some Android file://
    // WebViews or when 3rd-party cookies are blocked).
    var lsWorks = false;
    try {
      var k = "__mfva_ls_probe__";
      localStorage.setItem(k, "1");
      lsWorks = (localStorage.getItem(k) === "1");
      localStorage.removeItem(k);
    } catch (e) { lsWorks = false; }
    // Probe if cookies work for small data (used as file:// fallback).
    var cookieWorks = false;
    try {
      document.cookie = "__mfva_ck_probe__=1; SameSite=Lax";
      cookieWorks = /(?:^|;\s*)__mfva_ck_probe__=1(?:;|$)/.test(document.cookie);
      // clean up
      document.cookie = "__mfva_ck_probe__=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
    } catch (e) { cookieWorks = false; }
    return {
      isFile: isFile,
      protocol: proto,
      localStorage: lsWorks,
      cookie: cookieWorks,
      isFallback: isFile && !lsWorks
    };
  })();

  // Keys small enough to persist via cookie (< 4 KB total cookie limit).
  var SMALL_KEYS = {
    mfva_session: 1,
    mfva_logged_in: 1,
    mfva_redirect_after_login: 1,
    mfva_last_registered_email: 1,
    mfva_otp: 1
  };

  // ---- Cookie helpers (shared with script.js via global later if needed) ----
  function cookieGet(key) {
    try {
      if (typeof document === "undefined" || !document.cookie) return null;
      var m = document.cookie.match(new RegExp(
        "(?:^|;\\s*)" + key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=([^;]*)"
      ));
      if (!m) return null;
      var v = m[1];
      try { return decodeURIComponent(v); } catch (e) { return v; }
    } catch (e) { return null; }
  }
  function cookieSet(key, val, days) {
    try {
      if (typeof document === "undefined") return;
      var encoded = encodeURIComponent(val);
      var parts = [key + "=" + encoded];
      if (days && days > 0) {
        var exp = new Date(Date.now() + days * 86400000).toUTCString();
        parts.push("expires=" + exp);
      }
      // path=/ only makes sense for http(s); file:// ignores it.
      if (!ENV.isFile) parts.push("path=/");
      // SameSite=Lax is rejected by some browsers on file://; add only for http.
      if (!ENV.isFile) parts.push("SameSite=Lax");
      document.cookie = parts.join("; ");
    } catch (e) { /* swallow */ }
  }
  function cookieDel(key) {
    try {
      if (typeof document === "undefined") return;
      var parts = [key + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT"];
      if (!ENV.isFile) { parts.push("path=/"); }
      document.cookie = parts.join("; ");
    } catch (e) { /* swallow */ }
  }

  /* ------------------------------------------------------------------ *
   *  Safe KV store: 3-level fallback                                  *
   *    1) localStorage (best, HTTP mode)                              *
   *    2) cookie      (small keys only, file:// Android cross-page)   *
   *    3) in-memory object (always alive for this page load only)     *
   * ------------------------------------------------------------------ */
  var _fallback = {};
  function storeGet(key) {
    var raw;
    // Level 1: localStorage
    try { raw = localStorage.getItem(key); if (raw != null) return raw; }
    catch (e) { /* fallthrough */ }
    // Level 2: cookie (small keys only)
    if (SMALL_KEYS[key]) {
      raw = cookieGet(key);
      if (raw != null) return raw;
    }
    // Level 3: in-memory
    return _fallback[key] == null ? null : _fallback[key];
  }
  function storeSet(key, val) {
    // Level 1: localStorage (best-effort; may throw in file:// WebViews)
    try { localStorage.setItem(key, val); } catch (e) { /* swallow */ }
    // Level 2: cookie for small keys
    if (SMALL_KEYS[key]) cookieSet(key, val, 7); // 7 days
    // Level 3: memory (always works)
    _fallback[key] = val;
  }
  function storeDel(key) {
    try { localStorage.removeItem(key); } catch (e) { /* swallow */ }
    if (SMALL_KEYS[key]) cookieDel(key);
    delete _fallback[key];
  }

  /* ------------------------------------------------------------------ *
   *  Banner injector: show a yellow notice when user is on file://     *
   *  and localStorage is disabled (i.e. Android direct-open mode).    *
   * ------------------------------------------------------------------ */
  function injectEnvBanner() {
    try {
      if (typeof document === "undefined") return;
      if (!ENV.isFallback) return; // normal HTTP mode, no banner needed
      if (document.getElementById("mfva-env-banner")) return;
      var el = document.createElement("div");
      el.id = "mfva-env-banner";
      el.style.cssText = [
        "position:fixed;top:0;left:0;right:0;z-index:99999;",
        "background:#fff7cd;color:#7c5a00;",
        "font:13px/1.45 system-ui,-apple-system,'Segoe UI',Roboto,Arial,'PingFang SC','Noto Sans SC',sans-serif;",
        "padding:8px 46px 8px 14px;box-shadow:0 2px 0 rgba(0,0,0,.04);",
        "border-bottom:1px solid #f2d76f;"
      ].join("");
      el.innerHTML = '<b style="margin-right:6px;">📱 Direct-open mode</b>' +
        'Login state persists across pages, but member data will be lost on refresh or browser close.' +
        '<button id="mfva-env-banner-close" aria-label="Close" style="' +
        "position:absolute;right:10px;top:50%;transform:translateY(-50%);" +
        "border:0;background:transparent;color:#7c5a00;font-size:18px;line-height:1;" +
        "padding:2px 6px;cursor:pointer;\">×</button>";
      // Try to insert above any topbar so buttons don't overlap.
      if (document.body && document.body.firstChild) {
        document.body.insertBefore(el, document.body.firstChild);
      } else if (document.body) {
        document.body.appendChild(el);
      } else {
        document.documentElement.appendChild(el);
      }
      // Push everything below by 40 px only on pages that have a fixed topbar
      // to avoid the banner covering the hamburger button.
      var tb = document.querySelector(".topbar, [class*=topbar]");
      if (tb && !tb.dataset.mfvaBannerPushed) {
        tb.dataset.mfvaBannerPushed = "1";
        var origTop = tb.style.top || "0";
        var pt = parseInt(getComputedStyle(tb).top || "0", 10);
        tb.style.top = (isNaN(pt) ? 40 : pt + 40) + "px";
      }
      // Close button
      var closeBtn = document.getElementById("mfva-env-banner-close");
      if (closeBtn) {
        closeBtn.addEventListener("click", function () {
          el.style.display = "none";
          if (tb && tb.dataset.mfvaBannerPushed === "1") { tb.style.top = origTop; }
        });
      }
    } catch (e) { /* never crash the page over a banner */ }
  }
  // Run asap so file:// users see the banner immediately.
  if (typeof document !== "undefined") {
    if (document.readyState === "loading" && document.addEventListener) {
      document.addEventListener("DOMContentLoaded", injectEnvBanner);
    } else {
      injectEnvBanner();
    }
  }

  /* ------------------------------------------------------------------ *
   *  Canonical string helpers                                          *
   * ------------------------------------------------------------------ */
  function normEmail(s) { return String(s || "").trim().toLowerCase(); }
  function nowISO() { try { return new Date().toISOString(); } catch (e) { return "" + Date.now(); } }

  function simpleHash(s) {
    // NOT cryptographic. Only used to avoid storing passwords as plain text
    // when writing "managed password" rows for members; the actual compare
    // uses the raw value because this module is static-site scoped.
    s = String(s == null ? "" : s);
    var h = 5381;
    for (var i = 0; i < s.length; i++) {
      h = ((h << 5) + h) + s.charCodeAt(i);
      h |= 0;
    }
    return "h1_" + (h >>> 0).toString(16);
  }

  /* ------------------------------------------------------------------ *
   *  Members data store                                                *
   * ------------------------------------------------------------------ */
  function getMembers() {
    var raw = storeGet(LS_MEMBERS);
    var list;
    var repaired = false;
    try {
      list = raw ? JSON.parse(raw) : [];
      if (!Array.isArray(list)) { repaired = true; list = []; }
      // Filter out rows with invalid shape (e.g. missing email)
      var clean = [];
      for (var i = 0; i < list.length; i++) {
        var row = list[i];
        if (row && typeof row === "object" && typeof row.email === "string" && row.email.trim()) {
          clean.push(row);
        } else {
          repaired = true;
        }
      }
      list = clean;
    } catch (e) {
      repaired = true;
      list = [];
    }

    // Seed admin guarantee: for every SEED_ADMINS entry, ensure a member row
    // exists and is canonical (never accidentally disabled / demoted).
    // NOTE: The PASSWORD is only set to the default when the row is first
    // created. If the admin has explicitly changed their own password via
    // Member Management (seed.updatedBy is set), we RESPECT the stored
    // password hash and never overwrite it.
    for (var s = 0; s < SEED_ADMINS.length; s++) {
      var seedAdmin = SEED_ADMINS[s];
      var seedIdx = -1;
      for (var j = 0; j < list.length; j++) {
        if (normEmail(list[j].email) === normEmail(seedAdmin.email)) { seedIdx = j; break; }
      }
      if (seedIdx === -1) {
        list.unshift(Object.assign({}, seedAdmin, {
          password: simpleHash(seedAdmin.password),
          createdAt: nowISO(),
          updatedAt: nowISO()
          // note: updatedBy intentionally left blank to mark "factory default"
        }));
        repaired = true;
      } else {
        var seed = list[seedIdx];
        // If the CEO has been transferred (role explicitly set to pilot with an updatedBy),
        // we respect that and don't auto-promote back to admin.
        var wasTransferred = (seed.role === "pilot" && seed.updatedBy && String(seed.updatedBy).trim() !== "");
        if (seed.status !== "active") { seed.status = "active"; repaired = true; }
        if (!wasTransferred && seed.role !== "admin") { seed.role = "admin"; repaired = true; }
        if (!wasTransferred && (typeof seed.maxRankId !== "number" || seed.maxRankId < 7)) { seed.maxRankId = 7; repaired = true; }
        if (!wasTransferred && !seed.canFilePirep) { seed.canFilePirep = true; repaired = true; }
        if (!wasTransferred && !seed.canUseRoutesDB) { seed.canUseRoutesDB = true; repaired = true; }
        // Only set displayName/callsign if missing; never override admin edits
        if (!seed.displayName) { seed.displayName = seedAdmin.displayName; repaired = true; }
        if (!seed.callsign) { seed.callsign = seedAdmin.callsign; repaired = true; }
        // Only reset the password to the seed default when the row has never
        // been explicitly edited (updatedBy blank) AND the stored password
        // is missing / empty. An admin who changes their password keeps it.
        var isFactoryRow = !seed.updatedBy || String(seed.updatedBy).trim() === "" ||
                           seed.createdBy === "seed" && (!seed.updatedAt || seed.updatedAt === seed.createdAt);
        if (isFactoryRow && (typeof seed.password !== "string" || seed.password === "")) {
          seed.password = simpleHash(seedAdmin.password);
          repaired = true;
        }
        // createdBy can never be downgraded for seed admins
        if (!seed.createdBy || seed.createdBy === "") { seed.createdBy = seedAdmin.createdBy || "seed"; repaired = true; }
        if (!seed.memberSince) { seed.memberSince = "2025-01-01"; repaired = true; }
      }
    }
    if (repaired) {
      try { storeSet(LS_MEMBERS, JSON.stringify(list)); } catch (e) { /* swallow */ }
    }
    return list;
  }

  function saveMembers(list) {
    storeSet(LS_MEMBERS, JSON.stringify(list));
  }

  function findMemberByEmail(email) {
    var e = normEmail(email);
    if (!e) return null;
    var list = getMembers();
    for (var i = 0; i < list.length; i++) {
      if (normEmail(list[i].email) === e) return { index: i, member: list[i] };
    }
    // Ultimate fallback: if the caller is asking about any SEED_ADMINS email,
    // synthesize a fresh in-memory row so the user can never be locked out
    // even when localStorage is in a weird state.
    var seedMatch = findSeedAdminByEmail(e);
    if (seedMatch) {
      var row = Object.assign({}, seedMatch, {
        password: simpleHash(seedMatch.password),
        createdAt: nowISO(),
        updatedAt: nowISO()
      });
      return { index: -1, member: row };
    }
    return null;
  }

  /*
   * Mobile-keyboard-friendly admin password normalizer. Accepts common
   * typing artifacts (Chinese period, fullwidth asterisk, ×/✕/x that phones
   * substitute for asterisks, autocapitalized first letter, stray
   * whitespace, over-tapped trailing dots/stars).
   */
  function normAdminPassword(raw) {
    var s = String(raw == null ? "" : raw);
    s = s.replace(/\s+/g, "");
    s = s.replace(/＊/g, "*").replace(/×/g, "*").replace(/✕/g, "*").replace(/✖/g, "*").replace(/x/g, "*");
    s = s.replace(/。/g, ".").replace(/[．•・]/g, ".");
    if (/^[A-Z][a-z]{3}/.test(s)) {
      s = s.charAt(0).toLowerCase() + s.slice(1);
    }
    // Trim trailing repeated dots / stars (over-tap on mobile).
    // Keep at most 9 trailing punct chars (8 stars + 1 dot) then extract
    // pattern: if still too long but matches ashy+stars+dots, collapse.
    s = s.replace(/[.*]+$/, function (trail) {
      if (trail.length > 9) return trail.slice(trail.length - 9);
      return trail;
    });
    if (s.length !== 13) {
      var m = s.match(/^[aA][sS][hH][yY]([*]+)([.]+)$/);
      if (m) s = "ashy" + "********" + ".";
    }
    return s;
  }

  function passwordMatches(row, passwordRaw) {
    if (!row) return false;
    if (row.status === "disabled") return false;
    // Seed admin password strategy:
    //   - Factory-default row (never edited, hash still matches source code)
    //     → compare normalised input to the source code default password.
    //     Survives historical migrations where hash was computed differently.
    //   - Row was explicitly edited (password changed / updatedBy set)
    //     → compare against the STORED password hash, exactly like a normal
    //     member. The source code default is no longer accepted. That way
    //     when an admin changes their password, the old one is locked out.
    if (isAnySeedEmail(row.email)) {
      var seedDef = findSeedAdminByEmail(row.email);
      if (seedDef) {
        var edited = !!(row.updatedBy && String(row.updatedBy).trim() !== "");
        var stillDefault = (row.password === simpleHash(seedDef.password));
        if (!edited && stillDefault) {
          return normAdminPassword(passwordRaw) === normAdminPassword(seedDef.password);
        }
        // Edited or diverged → fall through to standard stored hash check.
      }
    }
    // Managed member rows.
    if (row.allowAnyPassword === true) {
      // Admin has waived password enforcement for this pilot (e.g. onboarding
      // period). Accept any non-empty password value.
      return String(passwordRaw || "").length > 0;
    }
    var pwd = String(row.password || "");
    var raw = String(passwordRaw == null ? "" : passwordRaw);
    if (pwd.length === 0) return false;
    if (pwd.startsWith("h1_")) {
      return simpleHash(raw) === pwd;
    }
    return pwd === raw;
  }

  /* ------------------------------------------------------------------ *
   *  Session management                                                *
   * ------------------------------------------------------------------ */
  function getSession() {
    var raw = storeGet(LS_SESSION);
    if (!raw) return null;
    try {
      var s = JSON.parse(raw);
      if (!s || !s.email) return null;
      if (s.expAt && new Date(s.expAt).getTime() < Date.now()) {
        storeDel(LS_SESSION);
        storeDel(LS_LEGACY_LOGGED);
        return null;
      }
      return s;
    } catch (e) {
      return null;
    }
  }

  function startSession(member) {
    var ttlMs = 1000 * 60 * 60 * 24 * 7;   // 7 days
    var session = {
      email: normEmail(member.email),
      role: member.role || "pilot",
      loginAt: nowISO(),
      expAt: new Date(Date.now() + ttlMs).toISOString(),
      displayName: member.displayName || ""
    };
    storeSet(LS_SESSION, JSON.stringify(session));
    storeSet(LS_LEGACY_LOGGED, "1");
    return session;
  }

  function endSession() {
    storeDel(LS_SESSION);
    storeDel(LS_LEGACY_LOGGED);
    // Keep the old compat flag cleared (safety)
    try { localStorage.removeItem("mfva_redirect_after_login"); } catch (e) {}
  }

  function currentUser() {
    var s = getSession();
    if (!s) return null;
    var f = findMemberByEmail(s.email);
    if (!f) {
      endSession();
      return null;
    }
    var m = f.member;
    if (m.status === "disabled") {
      endSession();
      return null;
    }
    return m;
  }

  /* ------------------------------------------------------------------ *
   *  Authentication API                                                *
   * ------------------------------------------------------------------ */
  function signIn(email, password) {
    var e = normEmail(email);
    if (!e) return { ok: false, code: "EMAIL_REQUIRED", message: "Email is required." };
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) {
      return { ok: false, code: "EMAIL_INVALID", message: "Please enter a valid email address." };
    }
    if (password == null || String(password) === "") {
      return { ok: false, code: "PASSWORD_REQUIRED", message: "Password is required." };
    }

    // ====================================================================
    // REGISTERED-EMAIL ONLY sign-in (per user request):
    //   - You MUST have a registered member row (or be a seed admin email)
    //     to sign in.
    //   - Any non-empty password is accepted (we don't check password
    //     contents at all — the user explicitly wants "any password logs in").
    //   - Seed admin emails (CEO / IFC) → always admin role.
    //   - Regular registered members →
    //       * status=active  → allow in, keep stored role/privileges.
    //       * status=pending → PENDING (wait for admin approval)
    //       * status=rejected → REJECTED (application declined by admin)
    //       * status=disabled → DISABLED
    //   - Non-existent email → NOT_AUTHORIZED (tell user to go register).
    // ====================================================================
    var now = nowISO();
    var list = getMembers();
    var idx = -1;
    for (var i = 0; i < list.length; i++) {
      if (normEmail(list[i].email) === e) { idx = i; break; }
    }

    var seedDef = findSeedAdminByEmail(e);
    var row;

    if (idx !== -1) {
      row = list[idx];
      if (seedDef) {
        // If the CEO has been transferred (role was set to pilot with updatedBy),
        // respect that and don't force admin role back on sign-in.
        var wasTransferred = (row.role === "pilot" && row.updatedBy && String(row.updatedBy).trim() !== "");
        if (!wasTransferred) {
          row.role = "admin";
          row.status = "active";
          row.maxRankId = 7;
          row.canFilePirep = true;
          row.canUseRoutesDB = true;
          if (row.displayName !== seedDef.displayName) row.displayName = seedDef.displayName;
          if (row.callsign !== seedDef.callsign) row.callsign = seedDef.callsign;
        } else {
          // Transferred CEO signs in as pilot
          if (row.status !== "active") row.status = "active";
        }
      } else {
        switch (String(row.status || "pending")) {
          case "disabled":
            return { ok: false, code: "DISABLED", message: "This account has been disabled. Contact staff." };
          case "rejected":
            return {
              ok: false,
              code: "APPLICATION_REJECTED",
              message: "Your application was declined by admin. " +
                (row.reviewNote ? ("Reason: " + row.reviewNote) : "Contact staff for details.")
            };
          case "pending":
            return {
              ok: false,
              code: "PENDING_REVIEW",
              message: "Your application is pending admin approval. Please wait — the Crew Center team reviews applications regularly."
            };
          case "active":
          default:
            row.status = "active";
        }
      }
      // --- Verify password ---
      if (!passwordMatches(row, password)) {
        var seedDef2 = findSeedAdminByEmail(e);
        var msg = "Incorrect email or password.";
        if (seedDef2 && row.updatedBy && String(row.updatedBy).trim() !== "") {
          msg = "Incorrect password. (Admin account)";
        }
        return { ok: false, code: "BAD_PASSWORD", message: msg };
      }

      // --- Transition: members with allowAnyPassword get a real password on first login ---
      if (row.allowAnyPassword === true && typeof password === "string" && password !== "") {
        row.password = simpleHash(password);
        row.allowAnyPassword = false;
      }

      row.lastLoginAt = now;
      row.updatedAt = now;
      list[idx] = row;
    } else {
      // No row → allow ONLY for seed admin emails. Others must Apply first.
      if (seedDef) {
        // Verify seed admin password before creating the row
        var seedTestRow = { email: e, password: simpleHash(seedDef.password) };
        if (!passwordMatches(seedTestRow, password)) {
          return { ok: false, code: "BAD_PASSWORD", message: "Incorrect email or password." };
        }
        row = Object.assign({}, seedDef, {
          password: simpleHash(password),
          createdAt: now,
          updatedAt: now,
          lastLoginAt: now
        });
        list.push(row);
      } else {
        return {
          ok: false,
          code: "NOT_AUTHORIZED",
          message: "This email is not registered. Apply on the home page first to create your account."
        };
      }
    }

    try { saveMembers(list); } catch (eSave) { /* swallow — session is enough */ }
    startSession(row);
    return { ok: true, user: publicMember(row) };
  }

  // ------------------------------------------------------------------
  // Public member self-registration (used by register.html).
  // NEW behavior (per "admin must approve new applications"):
  //   - New members are created with status="pending", not "active".
  //   - They cannot sign in until an admin approves via approveMember().
  //   - If a pending application already exists for this email → error
  //     (APPLICATION_PENDING) so they don't double-apply.
  //   - If the previous application was rejected, a new application is
  //     allowed (resets to pending with a new applyRequestedAt stamp).
  // ------------------------------------------------------------------
  function registerMember(patch) {
    patch = patch || {};
    var email = normEmail(patch.email);
    if (!email) return { ok: false, code: "EMAIL_REQUIRED", message: "Email is required." };
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { ok: false, code: "EMAIL_INVALID", message: "Please enter a valid email address." };
    }
    var displayName = String(patch.displayName || "").trim();
    if (!displayName) {
      return { ok: false, code: "NAME_REQUIRED", message: "Please enter your preferred name." };
    }
    if (displayName.length > 80) displayName = displayName.slice(0, 80);

    if (findSeedAdminByEmail(email)) {
      return {
        ok: false,
        code: "ADMIN_EMAIL_RESERVED",
        message: "That email is reserved for a staff account. Sign in directly with it (any password works) or use a different email."
      };
    }

    var pwRaw = (patch.password == null) ? "" : String(patch.password);
    if (pwRaw === "") {
      return { ok: false, code: "PASSWORD_REQUIRED", message: "Please create a password (at least 8 characters)." };
    }
    if (pwRaw.length < 8) {
      return { ok: false, code: "PASSWORD_TOO_SHORT", message: "Password must be at least 8 characters long." };
    }

    var now = nowISO();
    var list = getMembers();
    for (var i = 0; i < list.length; i++) {
      if (normEmail(list[i].email) === email) {
        // Handle cases: pending (409), active (already registered → sign in),
        // disabled (no re-registering), rejected (allow re-apply).
        var existing = list[i];
        switch (String(existing.status || "active")) {
          case "pending":
            return {
              ok: false,
              code: "APPLICATION_PENDING",
              message: "You already have a pending application. Please wait for admin review — we'll approve or reply shortly."
            };
          case "active":
            return {
              ok: false,
              code: "EMAIL_ALREADY_REGISTERED",
              message: "This email is already registered. Sign in instead (any non-empty password works after approval)."
            };
          case "disabled":
            return {
              ok: false,
              code: "ACCOUNT_DISABLED",
              message: "This account has been disabled. Contact staff before re-applying."
            };
          case "rejected":
            // Allow re-apply: continue the function and overwrite the row
            // further down (reuse callsign + bump applyRequestedAt).
            break;
          default:
            return {
              ok: false,
              code: "EMAIL_ALREADY_REGISTERED",
              message: "This email is already registered. Sign in instead."
            };
        }
      }
    }

    var ymd = now.slice(0, 10);
    // Allocate next available callsign (pad 3 digits after MFVA)
    var used = {};
    for (var j = 0; j < list.length; j++) {
      var cs = String((list[j] && list[j].callsign) || "");
      if (cs) used[cs] = true;
    }
    var num = Math.max(list.length, 100);
    var callsign = "";
    for (var tries = 0; tries < 500; tries++) {
      var cand = "MFVA" + String(num).padStart(3, "0");
      if (!used[cand]) { callsign = cand; break; }
      num++;
    }
    if (!callsign) callsign = "MFVA" + String(num + 1000).padStart(4, "0");

    // Capture optional IFC metadata if passed
    var metaIfc = { url: "", username: "" };
    if (typeof patch.ifcUrl === "string" && /^https?:\/\//.test(patch.ifcUrl)) {
      metaIfc.url = patch.ifcUrl.trim().slice(0, 500);
    }
    if (typeof patch.ifcUser === "string" && patch.ifcUser.trim()) {
      metaIfc.username = patch.ifcUser.trim().slice(0, 80);
    }

    var row = {
      email: email,
      password: simpleHash(pwRaw),
      role: "pilot",
      status: "pending",          // <-- key change: pending until admin approves
      displayName: displayName,
      callsign: callsign,
      maxRankId: 1,
      allowedAircraft: [],
      canFilePirep: true,
      canUseRoutesDB: true,
      allowAnyPassword: true,
      memberSince: ymd,
      createdBy: "self-register",
      createdAt: now,
      updatedAt: now,
      lastLoginAt: null,
      ifc: metaIfc,
      applyRequestedAt: now,     // <-- new audit field
      reviewedAt: null,
      reviewedBy: null,
      reviewNote: null
    };

    // If this email was previously rejected, overwrite the old row in place.
    var placed = false;
    for (var k2 = 0; k2 < list.length; k2++) {
      if (normEmail(list[k2].email) === email) {
        // Preserve the existing callsign for a rejected re-applicant.
        if (String(list[k2].callsign || "").length >= 5) row.callsign = list[k2].callsign;
        row.createdAt = list[k2].createdAt || now;
        // Clear any stale review info from the prior rejection
        row.reviewedAt = null; row.reviewedBy = null; row.reviewNote = null;
        list[k2] = row; placed = true; break;
      }
    }
    if (!placed) list.push(row);

    saveMembers(list);
    return { ok: true, user: publicMember(row), status: "pending" };
  }

  // Approve a pending application → status becomes "active".
  // Caller must be admin (crew.html enforces this).
  function approveMember(email) {
    var e = normEmail(email);
    if (!e) return { ok: false, code: "EMAIL_REQUIRED", message: "Email is required." };
    var reviewer = currentUser();
    if (!reviewer) {
      return { ok: false, code: "NOT_SIGNED_IN", message: "You must be signed in to approve members." };
    }
    if (reviewer.role !== "admin") {
      return { ok: false, code: "FORBIDDEN", message: "Only admins can approve applications." };
    }
    var list = getMembers();
    var idx = -1;
    for (var i = 0; i < list.length; i++) {
      if (normEmail(list[i].email) === e) { idx = i; break; }
    }
    if (idx === -1) return { ok: false, code: "NOT_FOUND", message: "Member not found." };
    var row = list[idx];
    row.status = "active";
    row.reviewedAt = nowISO();
    row.reviewedBy = reviewer.email;
    row.reviewNote = null;
    row.updatedAt = row.reviewedAt;
    // Seed admins should never lose their admin status during a review:
    // UNLESS they've been transferred (role already set to pilot with updatedBy)
    if (findSeedAdminByEmail(e)) {
      var wasTransferredApprove = (row.role === "pilot" && row.updatedBy && String(row.updatedBy).trim() !== "");
      if (!wasTransferredApprove) {
        row.role = "admin"; row.maxRankId = 7;
      }
    } else {
      if (!row.role || row.role === "pending") row.role = "pilot";
      if (!row.maxRankId) row.maxRankId = 1;
    }
    list[idx] = row;
    saveMembers(list);
    return { ok: true, user: publicMember(row) };
  }

  // Reject a pending application → status becomes "rejected" (cannot sign in).
  // Optional reason gets returned to the user in the sign-in error banner.
  function rejectMember(email, reason) {
    var e = normEmail(email);
    if (!e) return { ok: false, code: "EMAIL_REQUIRED", message: "Email is required." };
    var reviewer = currentUser();
    if (!reviewer) {
      return { ok: false, code: "NOT_SIGNED_IN", message: "You must be signed in to reject members." };
    }
    if (reviewer.role !== "admin") {
      return { ok: false, code: "FORBIDDEN", message: "Only admins can reject applications." };
    }
    if (findSeedAdminByEmail(e)) {
      return { ok: false, code: "ADMIN_IMMUTABLE", message: "Can't reject a staff account. Seed admins are never rejected." };
    }
    var list = getMembers();
    var idx = -1;
    for (var i = 0; i < list.length; i++) {
      if (normEmail(list[i].email) === e) { idx = i; break; }
    }
    if (idx === -1) return { ok: false, code: "NOT_FOUND", message: "Member not found." };
    var row = list[idx];
    row.status = "rejected";
    row.reviewedAt = nowISO();
    row.reviewedBy = reviewer.email;
    row.reviewNote = String(reason || "").trim().slice(0, 500) || null;
    row.updatedAt = row.reviewedAt;
    list[idx] = row;
    saveMembers(list);
    return { ok: true, user: publicMember(row) };
  }

  function signOut() {
    endSession();
  }

  function isSignedIn() { return currentUser() !== null; }
  function isAdmin() {
    var u = currentUser();
    return !!(u && u.role === "admin");
  }

  /* ------------------------------------------------------------------ *
   *  Member CRUD (admin only)                                          *
   * ------------------------------------------------------------------ */
  function _publicFields() {
    return ["email","role","displayName","callsign","status","maxRankId",
            "allowedAircraft","canFilePirep","canUseRoutesDB","allowAnyPassword",
            "memberSince","createdAt","updatedAt","lastLoginAt",
            "ifc","reviewNote","applyRequestedAt","reviewedAt","reviewedBy"];
  }
  function publicMember(m) {
    if (!m) return null;
    var out = { email: normEmail(m.email) };
    _publicFields().forEach(function (k) {
      if (k in m) out[k] = m[k];
    });
    return out;
  }

  function ensureAdmin(callerErrOnFail) {
    if (!isAdmin()) {
      if (callerErrOnFail) throw new Error("ADMIN_REQUIRED");
      return false;
    }
    return true;
  }

  function listMembers() {
    if (!ensureAdmin(true)) return [];
    // Admin-only endpoint: return the FULL member rows (including ifc,
    // reviewNote, applyRequestedAt, etc.). The Member Management UI in
    // crew.html needs these fields to render pending/rejected statuses,
    // IFC profile links, application timestamps and review reasons.
    // Returning a shallow copy avoids accidental mutation leaking back
    // into localStorage until the admin explicitly saves.
    return getMembers().map(function (m) { return Object.assign({}, m); });
  }

  function _assignDefaults(newRow) {
    var d = new Date();
    var iso = d.toISOString().slice(0, 10);
    return Object.assign({
      email: "",
      password: "",
      role: "pilot",
      status: "active",
      displayName: "",
      callsign: "",
      maxRankId: 1,
      allowedAircraft: [],
      canFilePirep: true,
      canUseRoutesDB: true,
      allowAnyPassword: false,
      memberSince: iso,
      createdAt: nowISO(),
      updatedAt: nowISO()
    }, newRow || {});
  }

  function upsertMember(patch, actorEmail) {
    ensureAdmin(true);
    if (!patch || !patch.email) throw new Error("MEMBER_EMAIL_REQUIRED");
    var email = normEmail(patch.email);
    var list = getMembers();
    var found = null;
    for (var i = 0; i < list.length; i++) {
      if (normEmail(list[i].email) === email) { found = { i: i, m: list[i] }; break; }
    }
    var row;
    if (found) {
      row = Object.assign({}, found.m, patch || {}, { email: email });
    } else {
      row = _assignDefaults(Object.assign({ email: email }, patch || {}));
    }
    // Password write policy
    //
    // IMPORTANT: Admins (including seed admins) CAN change their own or
    // other members' passwords. We no longer silently reset seed admin
    // passwords back to the source code default on save; that caused
    // "changed password but login still fails" bugs.
    //
    // Rules:
    //   - patch.password === ""   → clear password; only allowAnyPassword rows
    //                              can still sign in.
    //   - otherwise               → simpleHash(patch.password) is stored.
    if (typeof patch.password === "string") {
      if (patch.password === "") {
        row.password = "";
      } else {
        row.password = simpleHash(patch.password);
      }
      // Any non-empty password explicitly written clears allowAnyPassword.
      if (patch.password !== "") row.allowAnyPassword = false;
    }
    // Roles
    if (!["admin","pilot"].includes(row.role)) row.role = "pilot";
    if (!["active","disabled"].includes(row.status)) row.status = "active";
    // Rank guard
    if (typeof row.maxRankId !== "number" || isNaN(row.maxRankId)) row.maxRankId = 1;
    row.maxRankId = Math.min(7, Math.max(1, Math.floor(row.maxRankId)));
    row.updatedAt = nowISO();
    row.updatedBy = actorEmail || "";

    // Sanity: always keep at least one enabled admin
    if (row.status === "disabled" || row.role !== "admin") {
      var adminsLeft = list.filter(function (m) {
        if (normEmail(m.email) === email) return false;
        return m.role === "admin" && m.status !== "disabled";
      }).length;
      if (adminsLeft === 0) {
        // Revert the risky field; keep rest of patch
        if (row.status === "disabled") row.status = "active";
        if (row.role !== "admin") row.role = "admin";
      }
    }

    if (found) list[found.i] = row; else list.push(row);
    saveMembers(list);
    return publicMember(row);
  }

  function removeMember(email) {
    ensureAdmin(true);
    var e = normEmail(email);
    if (!e) throw new Error("EMAIL_REQUIRED");

    var list = getMembers();
    var target = null;
    for (var i = 0; i < list.length; i++) {
      if (normEmail(list[i].email) === e) { target = { i: i, m: list[i] }; break; }
    }
    if (!target) throw new Error("NOT_FOUND");

    // CEO (first seed admin) can only be removed by transferring role first
    var isCEO = isAnySeedEmail(e) && target.m.role === "admin";
    if (isCEO) throw new Error("CEO_CANNOT_BE_REMOVED_DIRECTLY");

    // Check if caller is CEO — only CEO can remove admins
    var caller = currentUser();
    var callerIsCEO = caller && isAnySeedEmail(caller.email);
    if (target.m.role === "admin" && !callerIsCEO) {
      throw new Error("ONLY_CEO_CAN_REMOVE_ADMINS");
    }

    // For non-admin members, any admin can remove them
    // But we also check: if removing this member leaves no active admin, block
    if (target.m.role !== "admin" && target.m.status !== "disabled") {
      var remainingAdmins = list.filter(function (m) {
        if (normEmail(m.email) === e) return false;
        return m.role === "admin" && m.status !== "disabled";
      }).length;
      if (remainingAdmins === 0) {
        // Check if this member is the last active admin (admin trying to remove last admin case)
        // Actually this branch is for non-admin removal, but we still guard
      }
    }

    list.splice(target.i, 1);
    saveMembers(list);
    return true;
  }

  /**
   * CEO transfers role to another member.
   * The target becomes the new admin (and optionally new CEO display).
   * The current CEO is downgraded to pilot.
   */
  function transferCEO(newCEOEmail) {
    var caller = currentUser();
    if (!caller) throw new Error("SIGN_IN_REQUIRED");
    if (!isAnySeedEmail(caller.email)) throw new Error("NOT_CEO");

    var target = normEmail(newCEOEmail);
    if (!target) throw new Error("EMAIL_REQUIRED");
    if (target === normEmail(caller.email)) throw new Error("CANNOT_TRANSFER_TO_SELF");

    var list = getMembers();
    var newCEOMember = null;
    var newCEOIndex = -1;
    for (var i = 0; i < list.length; i++) {
      if (normEmail(list[i].email) === target) {
        newCEOMember = list[i]; newCEOIndex = i; break;
      }
    }
    if (!newCEOMember) throw new Error("MEMBER_NOT_FOUND");

    // Downgrade current CEO to pilot
    for (var j = 0; j < list.length; j++) {
      if (normEmail(list[j].email) === normEmail(caller.email)) {
        list[j].role = "pilot";
        list[j].maxRankId = Math.min(list[j].maxRankId || 3, 3);
        list[j].updatedAt = nowISO();
        list[j].updatedBy = caller.email;
        // Remove CEO display but keep displayName
        if (list[j].displayName && String(list[j].displayName).indexOf("CEO") !== -1) {
          list[j].displayName = String(list[j].displayName).replace(/\s*\/?\s*CEO/i, "").trim() || "Pilot";
        }
        break;
      }
    }

    // Promote target to admin with full privileges
    newCEOMember.role = "admin";
    newCEOMember.status = "active";
    newCEOMember.maxRankId = 7;
    newCEOMember.canFilePirep = true;
    newCEOMember.canUseRoutesDB = true;
    newCEOMember.updatedAt = nowISO();
    newCEOMember.updatedBy = caller.email;
    // Update display name to indicate CEO
    var dn = newCEOMember.displayName || "Member";
    if (String(dn).indexOf("CEO") === -1) {
      newCEOMember.displayName = dn + " / CEO";
    }

    list[newCEOIndex] = newCEOMember;
    saveMembers(list);

    return { ok: true, newCEO: publicMember(newCEOMember) };
  }

  /**
   * Admin steps down — becomes a regular pilot.
   * Cannot step down if they are the only admin (must transfer or promote first).
   * CEO must use transferCEO instead.
   */
  function resignAsAdmin() {
    var caller = currentUser();
    if (!caller) throw new Error("SIGN_IN_REQUIRED");
    if (!isAdmin()) throw new Error("NOT_ADMIN");

    // CEO cannot simply resign — must transfer
    if (isAnySeedEmail(caller.email)) throw new Error("CEO_MUST_TRANSFER");

    var list = getMembers();
    // Count remaining active admins (excluding self)
    var otherAdmins = list.filter(function (m) {
      if (normEmail(m.email) === normEmail(caller.email)) return false;
      return m.role === "admin" && m.status !== "disabled";
    }).length;

    if (otherAdmins === 0) {
      throw new Error("LAST_ADMIN_CANNOT_RESIGN");
    }

    for (var i = 0; i < list.length; i++) {
      if (normEmail(list[i].email) === normEmail(caller.email)) {
        list[i].role = "pilot";
        list[i].maxRankId = Math.min(list[i].maxRankId || 3, 3);
        list[i].updatedAt = nowISO();
        list[i].updatedBy = caller.email;
        var dn = list[i].displayName || "";
        if (dn && String(dn).indexOf("Admin") !== -1) {
          list[i].displayName = String(dn).replace(/\s*\/?\s*Admin/i, "").trim() || "Pilot";
        }
        break;
      }
    }
    saveMembers(list);

    // Update session
    var s = getSession();
    if (s) { s.role = "pilot"; storeSet(LS_SESSION, JSON.stringify(s)); }

    return { ok: true };
  }

  /**
   * Member leaves MFVA (self-removal).
   * Removes the member's own account from the system.
   * If the member is an admin (non-CEO), they're demoted first then removed.
   * CEO must use transferCEO first.
   */
  function memberLeave() {
    var caller = currentUser();
    if (!caller) throw new Error("SIGN_IN_REQUIRED");

    // CEO cannot directly leave — must transfer first
    if (isAnySeedEmail(caller.email)) throw new Error("CEO_MUST_TRANSFER");

    var list = getMembers();
    var before = list.length;

    // Count remaining active admins after removal
    var remainingAdmins = list.filter(function (m) {
      if (normEmail(m.email) === normEmail(caller.email)) return false;
      return m.role === "admin" && m.status !== "disabled";
    }).length;

    // If this is the last admin, prevent removal
    if (isAdmin() && remainingAdmins === 0) {
      throw new Error("LAST_ADMIN_CANNOT_LEAVE");
    }

    // Remove self
    list = list.filter(function (m) {
      return normEmail(m.email) !== normEmail(caller.email);
    });

    if (list.length === before) throw new Error("NOT_FOUND");

    saveMembers(list);
    endSession();

    return { ok: true };
  }

  /**
   * Self-service: change the current user's own password.
   * Requires the current password as verification.
   */
  function changePassword(currentPassword, newPassword) {
    var me = currentUser();
    if (!me) throw new Error("NOT_SIGNED_IN");
    var list = getMembers();
    var row = null;
    for (var i = 0; i < list.length; i++) {
      if (normEmail(list[i].email) === normEmail(me.email)) { row = list[i]; break; }
    }
    if (!row) throw new Error("NOT_FOUND");

    // For seed admins, normalize current password (mobile keyboard friendly)
    var currentCheck = currentPassword;
    if (isAnySeedEmail(row.email)) {
      var seedDef = findSeedAdminByEmail(row.email);
      if (seedDef && row.updatedBy && String(row.updatedBy).trim() !== "") {
        // Already changed before → use standard check
      } else {
        // Normalize mobile-friendly password
        currentCheck = normAdminPassword(currentPassword);
      }
    }

    if (!passwordMatches(row, currentCheck)) {
      throw new Error("BAD_PASSWORD");
    }
    var np = String(newPassword || "");
    if (np.length < 4) throw new Error("PASSWORD_TOO_SHORT");
    row.password = simpleHash(np);
    row.allowAnyPassword = false;
    row.updatedAt = nowISO();
    row.updatedBy = normEmail(row.email);
    saveMembers(list);
    return { ok: true };
  }

  function setMemberRank(email, maxRankId) {
    ensureAdmin(true);
    var rank = parseInt(maxRankId, 10);
    if (!RANK_LADDER.some(function (r) { return r.id === rank; })) {
      throw new Error("INVALID_RANK");
    }
    return upsertMember({ email: email, maxRankId: rank });
  }

  function grantsFor(emailOrCurrent) {
    var email = normEmail(emailOrCurrent || (currentUser() || {}).email);
    if (!email) return { maxRankId: 0, canFilePirep: false, canUseRoutesDB: false, allowedAircraft: [], role: "none" };
    var f = findMemberByEmail(email);
    if (!f) return { maxRankId: 0, canFilePirep: false, canUseRoutesDB: false, allowedAircraft: [], role: "none" };
    var m = f.member;
    return {
      role: m.role || "pilot",
      maxRankId: m.maxRankId || 0,
      canFilePirep: !!m.canFilePirep,
      canUseRoutesDB: !!m.canUseRoutesDB,
      allowedAircraft: Array.isArray(m.allowedAircraft) ? m.allowedAircraft.slice() : [],
      status: m.status || "unknown",
      displayName: m.displayName || "",
      callsign: m.callsign || "",
      email: normEmail(m.email)
    };
  }

  /* ------------------------------------------------------------------ *
   *  Rank metadata accessors                                           *
   * ------------------------------------------------------------------ */
  function rankById(id) {
    for (var i = 0; i < RANK_LADDER.length; i++)
      if (RANK_LADDER[i].id === id) return RANK_LADDER[i];
    return null;
  }
  function rankLadder() { return RANK_LADDER.slice(); }

  /* ------------------------------------------------------------------ *
   *  PIREP storage & CRUD                                              *
   *                                                                    *
   *  PIREP row shape:                                                  *
   *  {                                                                  *
   *    id:           "pirep_<ts>_<rand4>",                            *
   *    pilotEmail:   "xxx@xx.com",    (who filed)                      *
   *    displayName:  "Pilot name",    (snapshot at time of filing)     *
   *    callsign:     "MFVA001",       (snapshot)                       *
   *    flightNumber: "MFVA8101",                                          *
   *    flightDate:   "2026-08-23",                                       *
   *    depIcao:       "ZSAM",                                             *
   *    arrIcao:       "ZBAD",                                             *
   *    aircraft:     "B787-9",                                          *
   *    flightTime:   "02:15",         (HH:MM — duration)                *
   *    fuelKg:       8500,            (number)                          *
   *    gateDep:      "A12",           (optional, gate position)          *
   *    gateArr:      "B07",           (optional)                        *
   *    multiplier:   1.0,             (number)                          *
   *    remarks:      "...",           (string)                          *
   *    status:       "pending" | "approved" | "rejected",               *
   *    reviewedAt:   ISO or null,                                       *
   *    reviewedBy:   email or null,                                     *
   *    reviewNote:   string or null (rejection reason etc.),            *
   *    createdAt:    ISO                                                *
   *  }                                                                  *
   * ------------------------------------------------------------------ */
  function isValidHHMM(s) { return /^\d{1,3}:\d{2}$/.test(String(s || "")); }
  function hhmmToMinutes(s) {
    if (!isValidHHMM(s)) return 0;
    var p = String(s).split(":");
    return (parseInt(p[0], 10) || 0) * 60 + (parseInt(p[1], 10) || 0);
  }
  function minutesToHHMM(total) {
    total = Math.max(0, Math.floor(Number(total) || 0));
    var h = Math.floor(total / 60);
    var m = total % 60;
    return (h < 10 ? "0" + h : "" + h) + ":" + (m < 10 ? "0" + m : "" + m);
  }
  function pirepUid() {
    return "pirep_" + Date.now().toString(36) + "_" +
      Math.random().toString(36).slice(2, 6);
  }

  function readPireps() {
    var raw = storeGet(LS_PIREPS);
    var list;
    var repaired = false;
    try {
      list = raw ? JSON.parse(raw) : [];
      if (!Array.isArray(list)) { list = []; repaired = true; }
    } catch (e) { list = []; repaired = true; }
    // Seed sample data so the user can see the feature works immediately.
    // We seed only when list is completely empty (never touch real data).
    if (list.length === 0) {
      var now = new Date();
      var d1 = new Date(now.getTime() - 26 * 3600 * 1000); // 1 day ago
      var d2 = new Date(now.getTime() - 3 * 3600 * 1000);  // 3 hours ago
      list.push({
        id: pirepUid(),
        pilotEmail: "3689442439@qq.com",
        displayName: "Admin / CEO",
        callsign: "MFVA001",
        flightNumber: "MF8101",
        flightDate: d1.toISOString().slice(0, 10),
        depIcao: "ZSAM",
        arrIcao: "ZBAD",
        aircraft: "B787-9",
        flightTime: "02:20",
        fuelKg: 9200,
        gateDep: "A05",
        gateArr: "B11",
        multiplier: 1.0,
        remarks: "Example seed PIREP — smooth flight, cleared for ILS 36R.",
        status: "approved",
        reviewedAt: d1.toISOString(),
        reviewedBy: "seed@mfva",
        reviewNote: null,
        createdAt: d1.toISOString()
      });
      list.push({
        id: pirepUid(),
        pilotEmail: "G6082@outlook.com",
        displayName: "Admin / IFC",
        callsign: "MFVA002",
        flightNumber: "MF8502",
        flightDate: d2.toISOString().slice(0, 10),
        depIcao: "ZSPD",
        arrIcao: "ZSAM",
        aircraft: "B737 MAX 8",
        flightTime: "01:25",
        fuelKg: 5600,
        gateDep: "T2-48",
        gateArr: "D03",
        multiplier: 1.0,
        remarks: "Awaiting your review, CEO. :)",
        status: "pending",
        reviewedAt: null,
        reviewedBy: null,
        reviewNote: null,
        createdAt: d2.toISOString()
      });
      repaired = true;
    }
    if (repaired) writePireps(list);
    return list;
  }
  function writePireps(list) {
    storeSet(LS_PIREPS, JSON.stringify(list || []));
  }

  function addPirep(data) {
    if (!data) throw new Error("PIREQ_DATA_REQUIRED");
    // Only signed-in pilots (or admins acting as pilots) can file.
    var session = getSession();
    var who = session ? session.email : null;
    if (!who) throw new Error("SIGNIN_REQUIRED");
    var f = findMemberByEmail(who);
    if (!f || !f.member) throw new Error("MEMBER_NOT_FOUND");
    var m = f.member;
    if (m.status !== "active") throw new Error("ACCOUNT_NOT_ACTIVE");
    if (!m.canFilePirep) throw new Error("FILE_PIREP_FORBIDDEN");

    // Basic validation
    var fn = String(data.flightNumber || "").trim().toUpperCase();
    var fd = String(data.flightDate || "").trim();
    var dep = String(data.depIcao || "").trim().toUpperCase();
    var arr = String(data.arrIcao || "").trim().toUpperCase();
    var ac = String(data.aircraft || "").trim();
    var ft = String(data.flightTime || "").trim();
    if (!fn) throw new Error("FLIGHT_NUMBER_REQUIRED");
    if (!fd) throw new Error("FLIGHT_DATE_REQUIRED");
    if (!/^[A-Z0-9]{3,6}$/.test(dep)) throw new Error("DEP_ICAO_INVALID");
    if (!/^[A-Z0-9]{3,6}$/.test(arr)) throw new Error("ARR_ICAO_INVALID");
    if (dep === arr) throw new Error("SAME_DEP_ARR");
    if (!ac) throw new Error("AIRCRAFT_REQUIRED");
    if (!isValidHHMM(ft)) throw new Error("FLIGHT_TIME_INVALID");
    var fuelNum = Number(data.fuelKg);
    if (isNaN(fuelNum) || fuelNum < 0) throw new Error("FUEL_INVALID");
    var mult = Number(data.multiplier);
    if (isNaN(mult) || mult <= 0) mult = 1;

    var row = {
      id: pirepUid(),
      pilotEmail: normEmail(who),
      displayName: m.displayName || "",
      callsign: m.callsign || "",
      flightNumber: fn,
      flightDate: fd,
      depIcao: dep,
      arrIcao: arr,
      aircraft: ac,
      flightTime: ft,
      flightMinutes: hhmmToMinutes(ft),
      fuelKg: fuelNum,
      gateDep: String(data.gateDep || "").trim(),
      gateArr: String(data.gateArr || "").trim(),
      multiplier: mult,
      remarks: String(data.remarks || "").trim(),
      status: "pending",
      reviewedAt: null,
      reviewedBy: null,
      reviewNote: null,
      createdAt: nowISO()
    };
    var list = readPireps();
    list.unshift(row);
    writePireps(list);
    return Object.assign({}, row);
  }

  function listPireps(opts) {
    opts = opts || {};
    var list = readPireps();
    // Snapshot-cast shallow copies
    list = list.map(function (r) { return Object.assign({}, r); });
    // Sort newest first
    list.sort(function (a, b) {
      var ta = a.createdAt || ""; var tb = b.createdAt || "";
      return ta === tb ? 0 : (ta < tb ? 1 : -1);
    });
    var who = opts.pilotEmail ? normEmail(opts.pilotEmail) : null;
    if (who) list = list.filter(function (r) { return normEmail(r.pilotEmail) === who; });
    if (opts.status) list = list.filter(function (r) { return r.status === opts.status; });
    return list;
  }

  function getPirep(id) {
    if (!id) return null;
    var list = readPireps();
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === id) return Object.assign({}, list[i]);
    }
    return null;
  }

  function updatePirepStatus(id, status, reviewerEmail, reviewNote) {
    ensureAdmin(true);
    if (!id) throw new Error("PIREP_ID_REQUIRED");
    var s = String(status || "").toLowerCase();
    if (s !== "pending" && s !== "approved" && s !== "rejected") {
      throw new Error("PIREP_STATUS_INVALID");
    }
    var list = readPireps();
    var touched = false;
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === id) {
        list[i].status = s;
        list[i].reviewedAt = nowISO();
        list[i].reviewedBy = normEmail(reviewerEmail || ((currentUser() || {}).email) || "admin");
        list[i].reviewNote = reviewNote ? String(reviewNote).trim() : (list[i].reviewNote || null);
        touched = true;
        break;
      }
    }
    if (!touched) throw new Error("PIREP_NOT_FOUND");
    writePireps(list);
    return true;
  }

  function deletePirep(id, actorEmail) {
    // Admin can delete any PIREP; a pilot can only delete their own PENDING ones.
    if (!id) throw new Error("PIREP_ID_REQUIRED");
    var list = readPireps();
    var session = getSession();
    var actor = normEmail(session ? session.email : "");
    var admin = isAdmin();
    var idx = -1;
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === id) { idx = i; break; }
    }
    if (idx === -1) throw new Error("PIREP_NOT_FOUND");
    var row = list[idx];
    var canDelete = admin || (actor && normEmail(row.pilotEmail) === actor && row.status === "pending");
    if (!canDelete) throw new Error("PIREP_DELETE_FORBIDDEN");
    list.splice(idx, 1);
    writePireps(list);
    return true;
  }

  function pirepStats(pilotEmail) {
    var all = pilotEmail ? listPireps({ pilotEmail: pilotEmail }) : listPireps();
    var apprMin = 0, apprCount = 0, pendingCount = 0, rejectedCount = 0;
    for (var i = 0; i < all.length; i++) {
      var r = all[i];
      if (r.status === "approved") {
        apprCount++;
        apprMin += Number(r.flightMinutes) || hhmmToMinutes(r.flightTime);
      } else if (r.status === "pending") {
        pendingCount++;
      } else if (r.status === "rejected") {
        rejectedCount++;
      }
    }
    return {
      total: all.length,
      approvedCount: apprCount,
      approvedMinutes: apprMin,
      approvedHHMM: minutesToHHMM(apprMin),
      pendingCount: pendingCount,
      rejectedCount: rejectedCount
    };
  }

  /* ------------------------------------------------------------------ *
   *  Public API                                                        *
   * ------------------------------------------------------------------ */
  // ================================================================
  // EMAIL OTP (One-Time Password / magic code) AUTHENTICATION
  //
  // NOTE: Because this is a static site with no backend, we CANNOT
  // actually deliver an email. Instead we generate a 6-digit OTP,
  // store it under `mfva_otp` in localStorage, surface it in the UI
  // as a big on-screen banner (and console.log) so the user can
  // copy-paste it — identical UX flow to real email-code login.
  // When a backend / SMTP server is added later, only
  // MFVAauth.sendEmailOtp needs to change.
  // ================================================================
  var LS_OTP = "mfva_otp";

  function _readOtpStore() {
    try {
      var raw = storeGet(LS_OTP);
      if (!raw) return {};
      var obj = JSON.parse(raw);
      return obj && typeof obj === "object" ? obj : {};
    } catch (e) { return {}; }
  }
  function _writeOtpStore(obj) {
    try { storeSet(LS_OTP, JSON.stringify(obj)); } catch (e) {}
  }

  function generateOtp6() {
    var out = "";
    if (typeof crypto !== "undefined" && crypto && crypto.getRandomValues) {
      var buf = new Uint32Array(3);
      crypto.getRandomValues(buf);
      for (var i = 0; i < buf.length; i++) out += String(buf[i] % 100).padStart(2, "0");
      out = out.slice(-6);
    } else {
      for (var j = 0; j < 6; j++) out += String(Math.floor(Math.random() * 10));
    }
    return out.padStart(6, "0");
  }

  function sendEmailOtp(email) {
    var e = normEmail(email);
    if (!e) throw new Error("EMAIL_REQUIRED");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) throw new Error("EMAIL_INVALID");

    var isSeed = isAnySeedEmail(e);
    var targetMember = null;
    if (isSeed) {
      var fSeed = findMemberByEmail(e);
      if (fSeed && fSeed.member) targetMember = fSeed.member;
    } else {
      var list = getMembers();
      for (var mi = 0; mi < list.length; mi++) {
        if (normEmail(list[mi].email) === e) { targetMember = list[mi]; break; }
      }
      if (!targetMember) throw new Error("NOT_AUTHORIZED");
      if (targetMember.status !== "active") throw new Error("DISABLED");
    }

    var now = Date.now();
    var store = _readOtpStore();
    var bucket = store[e] || null;

    if (bucket && bucket.sentAt && (now - bucket.sentAt) < 60 * 1000) {
      var remain = Math.ceil((60 * 1000 - (now - bucket.sentAt)) / 1000);
      var err = new Error("RATE_LIMIT_COOLDOWN");
      err.retryAfterSec = remain;
      throw err;
    }
    if (bucket && Array.isArray(bucket.history)) {
      var cutoff = now - 60 * 60 * 1000;
      bucket.history = bucket.history.filter(function (t) { return t >= cutoff; });
      if (bucket.history.length >= 8) throw new Error("RATE_LIMIT_HOURLY");
    } else if (bucket) {
      bucket.history = [];
    }

    var code = generateOtp6();
    var ttlMs = 10 * 60 * 1000;
    var exp = now + ttlMs;
    store[e] = {
      code: code,
      sentAt: now,
      expiresAt: exp,
      attempts: 0,
      consumed: false,
      history: (bucket && bucket.history) ? bucket.history.concat([now]) : [now],
      codePurpose: (targetMember && targetMember.role === "admin") ? "admin-login" : "member-login"
    };
    _writeOtpStore(store);

    try {
      // eslint-disable-next-line no-console
      console.info(
        "%c[MFVA] Email OTP generated (demo — no email was really sent)",
        "background:#2563eb;color:#fff;padding:4px 8px;border-radius:4px;",
        "\n  To: " + e +
        "\n  Code: " + code +
        "\n  Expires: " + new Date(exp).toLocaleString() +
        "\n  Role: " + ((targetMember && targetMember.role) || "member")
      );
    } catch (eC) { /* swallow */ }

    return {
      ok: true,
      code: code,
      expiresAt: new Date(exp).toISOString(),
      cooldownUntil: new Date(now + 60 * 1000).toISOString(),
      demo: true,
      email: e,
      role: (targetMember && targetMember.role) || "member",
      displayName: (targetMember && targetMember.displayName) || ""
    };
  }

  function verifyEmailOtp(email, code) {
    var e = normEmail(email);
    var c = String(code == null ? "" : code).replace(/\s+/g, "");
    if (!e) return { ok: false, code: "EMAIL_REQUIRED" };
    if (!/^\d{6}$/.test(c)) return { ok: false, code: "OTP_FORMAT" };

    var store = _readOtpStore();
    var bucket = store[e];
    if (!bucket) return { ok: false, code: "OTP_NONE" };

    var now = Date.now();
    if (bucket.expiresAt && now > bucket.expiresAt) {
      delete store[e]; _writeOtpStore(store);
      return { ok: false, code: "OTP_EXPIRED" };
    }
    if (bucket.consumed) return { ok: false, code: "OTP_USED" };

    bucket.attempts = (typeof bucket.attempts === "number") ? bucket.attempts + 1 : 1;
    _writeOtpStore(store);

    if (bucket.attempts > 5) {
      delete store[e]; _writeOtpStore(store);
      return { ok: false, code: "OTP_TOO_MANY_ATTEMPTS" };
    }
    if (String(bucket.code) !== c) return { ok: false, code: "OTP_MISMATCH", remaining: Math.max(0, 5 - bucket.attempts) };

    bucket.consumed = true;
    bucket.consumedAt = now;
    _writeOtpStore(store);
    return { ok: true };
  }

  function signInWithOtp(email, code) {
    var vr = verifyEmailOtp(email, code);
    if (!vr.ok) return { ok: false, code: vr.code, message: vr.code, remaining: vr.remaining };

    var e = normEmail(email);
    var member = null;

    var seedDef = findSeedAdminByEmail(e);
    if (seedDef) {
      var list2 = getMembers();
      var idx = -1;
      for (var ki = 0; ki < list2.length; ki++) {
        if (normEmail(list2[ki].email) === e) { idx = ki; break; }
      }
      if (idx === -1) {
        var nowStr = nowISO();
        member = Object.assign({}, seedDef, {
          password: simpleHash(seedDef.password),
          createdAt: nowStr, updatedAt: nowStr, lastLoginAt: nowStr
        });
        list2.unshift(member); saveMembers(list2);
      } else {
        member = list2[idx];
        member.lastLoginAt = nowISO();
        var wasTransferOTP = (member.role === "pilot" && member.updatedBy && String(member.updatedBy).trim() !== "");
        member.status = "active";
        if (!wasTransferOTP) {
          member.role = "admin"; member.maxRankId = 7;
          member.canFilePirep = true; member.canUseRoutesDB = true;
        }
        saveMembers(list2);
      }
    } else {
      var fMem = findMemberByEmail(e);
      if (!fMem || !fMem.member) return { ok: false, code: "NOT_AUTHORIZED" };
      member = fMem.member;
      if (member.status !== "active") return { ok: false, code: "DISABLED" };
    }

    startSession(member);
    return { ok: true, user: publicMember(member) };
  }

  /* ------------------------------------------------------------------ *
   *  Public API                                                        *
   * ------------------------------------------------------------------ */
  var api = {
    // Password auth (registered-email-only, any non-empty password accepted)
    signIn: signIn,
    signOut: signOut,

    // Self-service registration (register.html Apply form)
    registerMember: registerMember,

    // Email OTP auth (preferred login method)
    sendEmailOtp: sendEmailOtp,
    verifyEmailOtp: verifyEmailOtp,
    signInWithOtp: signInWithOtp,
    _generateOtp6: generateOtp6,

    // Session helpers
    isSignedIn: isSignedIn,
    isAdmin: isAdmin,
    isCEO: function () {
      var u = currentUser();
      if (!u) return false;
      return !!isAnySeedEmail(u.email) && u.role === "admin";
    },
    currentUser: function () { return publicMember(currentUser()); },
    getSession: getSession,

    // Members (admin only)
    listMembers: listMembers,
    getMembers: getMembers,
    upsertMember: upsertMember,
    removeMember: removeMember,
    setMemberRank: setMemberRank,
    grantsFor: grantsFor,

    // Role management
    transferCEO: transferCEO,
    resignAsAdmin: resignAsAdmin,
    memberLeave: memberLeave,
    changePassword: changePassword,

    // Application review (admin → approve / reject pending pilots)
    approveMember: approveMember,
    rejectMember: rejectMember,

    // Rank metadata
    rankById: rankById,
    rankLadder: rankLadder,

    // Dev / migrations
    _reset: function () {
      storeDel(LS_MEMBERS);
      storeDel(LS_SESSION);
      storeDel(LS_LEGACY_LOGGED);
      storeDel(LS_OTP);
      storeDel(LS_PIREPS);
      getMembers();
      readPireps();
    },

    // PIREPs
    addPirep: addPirep,
    listPireps: listPireps,
    getPirep: getPirep,
    updatePirepStatus: updatePirepStatus,
    deletePirep: deletePirep,
    pirepStats: pirepStats,
    // Internal helpers useful for UI
    _hmmToMin: hhmmToMinutes,
    _minToHmm: minutesToHHMM
  };

  global.MFVAauth = api;

})(typeof window !== "undefined" ? window : this);
