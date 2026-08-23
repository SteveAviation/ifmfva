/*!
 * MFVA Cloud Sync — GitHub API backend
 * -------------------------------------
 * Replaces localStorage-only storage with GitHub repo as a shared
 * cloud database. All members and PIREPs are stored as JSON files
 * in the repository so every device sees the same data.
 *
 * Setup:
 *   1. Go to GitHub → Settings → Developer settings →
 *      Fine-grained personal access tokens
 *   2. Create a token with "Contents: Read and Write" for your repo
 *   3. Admin enters the token + repo info on the Crew Center page
 *      (stored in localStorage on admin's device only)
 *
 * Data layout in repo:
 *   data/members.json    — all member records
 *   data/pireps.json     — all PIREP records
 *
 * Security note: The token is stored in the admin's browser only.
 * Regular members do not need a token — they read public repo data
 * via the GitHub API (works for public repos without auth, rate-limited).
 * Writes (registration, PIREP submission) use the token.
 */
(function (root) {
  "use strict";

  var CONFIG_KEY = "mfva_github_config";
  var API_BASE = "https://api.github.com";

  // ---- Config management (admin device only) ----
  function getConfig() {
    try {
      var raw = localStorage.getItem(CONFIG_KEY);
      if (!raw) return null;
      var c = JSON.parse(raw);
      return c;
    } catch (e) { return null; }
  }

  function setConfig(cfg) {
    try { localStorage.setItem(CONFIG_KEY, JSON.stringify(cfg)); return true; }
    catch (e) { return false; }
  }

  function clearConfig() {
    try { localStorage.removeItem(CONFIG_KEY); } catch (e) {}
  }

  // ---- Token can also be embedded for all-users write access ----
  // If you set MFVA_GH_TOKEN in the code, all users can write.
  // Otherwise only admin device has the token.
  // >>> Put your GitHub Fine-grained PAT here <<<
  var EMBEDDED_TOKEN = "";

  // ---- Auto-detect repo from GitHub Pages URL ----
  function autoDetectRepo() {
    try {
      var href = window.location.href || "";
      // Match: https://<owner>.github.io/<repo>/...
      var m = href.match(/https?:\/\/([^./]+)\.github\.io\/([^/]+)/i);
      if (m) return { owner: m[1], repo: m[2] };
    } catch (e) {}
    return null;
  }

  function getWriteToken() {
    var cfg = getConfig();
    if (cfg && cfg.token) return cfg.token;
    return EMBEDDED_TOKEN;
  }

  function getRepoInfo() {
    var cfg = getConfig();
    if (cfg && cfg.owner && cfg.repo) return { owner: cfg.owner, repo: cfg.repo };
    // Auto-detect from URL (works on GitHub Pages)
    var auto = autoDetectRepo();
    if (auto) return auto;
    return null;
  }

  function hasConfig() {
    return !!getRepoInfo();
  }

  // ---- GitHub API helpers ----

  /**
   * Read a file from the repo via GitHub Contents API.
   * Works without auth for public repos (rate-limited to 60/hr).
   */
  function readFile(path) {
    var repo = getRepoInfo();
    if (!repo) return Promise.reject(new Error("NO_CONFIG"));

    var url = API_BASE + "/repos/" + repo.owner + "/" + repo.repo + "/contents/" + path;
    var token = getWriteToken();

    return fetch(url, {
      method: "GET",
      headers: {
        "Accept": "application/vnd.github+json",
        "Authorization": token ? ("Bearer " + token) : ""
      }
    }).then(function (resp) {
      if (resp.status === 404) return null; // File doesn't exist yet
      if (!resp.ok) throw new Error("GH_READ_" + resp.status);
      return resp.json();
    }).then(function (data) {
      if (!data) return { content: null, sha: null };
      // Decode base64 content
      var content = null;
      if (data.content) {
        try {
          // Handle base64 with potential padding issues
          var b64 = data.content.replace(/\n/g, "");
          content = decodeURIComponent(escape(atob(b64)));
        } catch (e) {
          try { content = atob(data.content.replace(/\n/g, "")); }
          catch (e2) { content = null; }
        }
      }
      return { content: content, sha: data.sha };
    });
  }

  /**
   * Write a file to the repo via GitHub Contents API.
   * Requires a token with Contents: Write permission.
   */
  function writeFile(path, content, sha, commitMsg) {
    var repo = getRepoInfo();
    if (!repo) return Promise.reject(new Error("NO_CONFIG"));
    var token = getWriteToken();
    if (!token) return Promise.reject(new Error("NO_TOKEN"));

    var url = API_BASE + "/repos/" + repo.owner + "/" + repo.repo + "/contents/" + path;
    var body = {
      message: commitMsg || ("Update " + path),
      content: btoa(unescape(encodeURIComponent(content)))
    };
    if (sha) body.sha = sha;

    return fetch(url, {
      method: "PUT",
      headers: {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    }).then(function (resp) {
      if (!resp.ok) {
        return resp.json().then(function (err) {
          throw new Error("GH_WRITE_" + resp.status + ": " + (err.message || ""));
        });
      }
      return resp.json();
    }).then(function (data) {
      return { ok: true, sha: data.content ? data.content.sha : null };
    });
  }

  // ---- High-level sync functions ----

  // In-memory cache to reduce API calls
  var _cache = {
    members: { data: null, sha: null, ts: 0 },
    pireps: { data: null, sha: null, ts: 0 }
  };
  var CACHE_TTL = 30000; // 30 seconds

  /**
   * Fetch members from GitHub (or cache).
   * Returns: { list: [...], sha: "..." }
   */
  function fetchMembers() {
    var now = Date.now();
    if (_cache.members.data && (now - _cache.members.ts) < CACHE_TTL) {
      return Promise.resolve({ list: _cache.members.data, sha: _cache.members.sha });
    }

    return readFile("data/members.json").then(function (result) {
      var list = [];
      if (result.content) {
        try { list = JSON.parse(result.content); } catch (e) { list = []; }
      }
      _cache.members = { data: list, sha: result.sha, ts: Date.now() };
      return { list: list, sha: result.sha };
    });
  }

  /**
   * Save members to GitHub.
   * Uses optimistic locking via SHA.
   */
  function pushMembers(list, commitMsg) {
    var json = JSON.stringify(list, null, 2);
    var sha = _cache.members.sha;

    return writeFile("data/members.json", json, sha, commitMsg || "Update members").then(function (r) {
      _cache.members = { data: list, sha: r.sha, ts: Date.now() };
      return r;
    });
  }

  /**
   * Fetch PIREPs from GitHub.
   */
  function fetchPireps() {
    var now = Date.now();
    if (_cache.pireps.data && (now - _cache.pireps.ts) < CACHE_TTL) {
      return Promise.resolve({ list: _cache.pireps.data, sha: _cache.pireps.sha });
    }

    return readFile("data/pireps.json").then(function (result) {
      var list = [];
      if (result.content) {
        try { list = JSON.parse(result.content); } catch (e) { list = []; }
      }
      _cache.pireps = { data: list, sha: result.sha, ts: Date.now() };
      return { list: list, sha: result.sha };
    });
  }

  /**
   * Save PIREPs to GitHub.
   */
  function pushPireps(list, commitMsg) {
    var json = JSON.stringify(list, null, 2);
    var sha = _cache.pireps.sha;

    return writeFile("data/pireps.json", json, sha, commitMsg || "Update PIREPs").then(function (r) {
      _cache.pireps = { data: list, sha: r.sha, ts: Date.now() };
      return r;
    });
  }

  /**
   * Force refresh cache (bypass TTL).
   */
  function clearCache() {
    _cache.members = { data: null, sha: null, ts: 0 };
    _cache.pireps = { data: null, sha: null, ts: 0 };
  }

  /**
   * Test the connection to GitHub.
   */
  function testConnection() {
    var repo = getRepoInfo();
    if (!repo) return Promise.reject(new Error("NO_CONFIG"));

    var url = API_BASE + "/repos/" + repo.owner + "/" + repo.repo;
    var token = getWriteToken();

    return fetch(url, {
      method: "GET",
      headers: {
        "Accept": "application/vnd.github+json",
        "Authorization": token ? ("Bearer " + token) : ""
      }
    }).then(function (resp) {
      if (!resp.ok) throw new Error("GH_TEST_" + resp.status);
      return resp.json();
    }).then(function (data) {
      return {
        ok: true,
        repo: data.full_name,
        private: data.private,
        canWrite: !!token
      };
    });
  }

  // ---- Export ----
  root.MFVAcloud = {
    getConfig: getConfig,
    setConfig: setConfig,
    clearConfig: clearConfig,
    hasConfig: hasConfig,
    getRepoInfo: getRepoInfo,
    getWriteToken: getWriteToken,

    fetchMembers: fetchMembers,
    pushMembers: pushMembers,
    fetchPireps: fetchPireps,
    pushPireps: pushPireps,
    clearCache: clearCache,
    testConnection: testConnection
  };

})(typeof window !== "undefined" ? window : this);
