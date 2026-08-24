/*!
 * MFVA Supabase Sync
 * ------------------
 * Syncs member data to a Supabase project so that applications filed on
 * one device are visible to the admin on every other device.
 *
 * Uses the Supabase REST API (PostgREST) directly — no SDK needed.
 * The anon key is safe to expose in frontend code when Row Level Security
 * is enabled (see supabase-schema.sql).
 *
 * Setup:
 *   1. Create a new project at supabase.com
 *   2. Run supabase-schema.sql in the SQL Editor
 *   3. Fill in SUPABASE_URL and SUPABASE_ANON_KEY below
 *      (Project Settings → API → Project URL + anon public key)
 */
(function (root) {
  "use strict";

  // ============================================================
  //  CONFIG — replace with your Supabase project values
  // ============================================================
  var SUPABASE_URL = "https://mexxmqnectzqkaevluwz.supabase.co";
  var SUPABASE_ANON_KEY = "sb_publishable_HtQ685W0ZA5-TVX4m1CXuA_YHkqMHNz";
  // ============================================================

  var REST_BASE = SUPABASE_URL + "/rest/v1";
  var TABLE = "members";

  function isConfigured() {
    return SUPABASE_URL.indexOf("YOUR-PROJECT") === -1 &&
           SUPABASE_ANON_KEY.indexOf("YOUR-ANON-KEY") === -1;
  }

  function headers(extra) {
    var h = {
      "apikey": SUPABASE_ANON_KEY,
      "Content-Type": "application/json"
    };
    if (extra) {
      Object.keys(extra).forEach(function (k) { h[k] = extra[k]; });
    }
    return h;
  }

  /**
   * Fetch all member records from Supabase.
   * Returns: Promise<array> — array of member objects (the .data field).
   */
  function fetchMembers() {
    if (!isConfigured()) return Promise.reject(new Error("NOT_CONFIGURED"));

    return fetch(REST_BASE + "/" + TABLE + "?select=data", {
      method: "GET",
      headers: headers()
    }).then(function (resp) {
      if (!resp.ok) throw new Error("SB_FETCH_" + resp.status);
      return resp.json();
    }).then(function (rows) {
      // Each row is { data: {...member} }
      var list = [];
      if (Array.isArray(rows)) {
        for (var i = 0; i < rows.length; i++) {
          if (rows[i] && rows[i].data) list.push(rows[i].data);
        }
      }
      return list;
    });
  }

  /**
   * Insert or update a single member by email (upsert).
   * Returns: Promise<{ok:true}>
   */
  function upsertMember(member) {
    if (!isConfigured()) return Promise.reject(new Error("NOT_CONFIGURED"));
    if (!member || !member.email) return Promise.reject(new Error("NO_EMAIL"));

    var body = JSON.stringify({
      email: member.email,
      data: member,
      updated_at: new Date().toISOString()
    });

    return fetch(REST_BASE + "/" + TABLE + "?on_conflict=email", {
      method: "POST",
      headers: headers({
        "Prefer": "resolution=merge-duplicates,return=minimal"
      }),
      body: body
    }).then(function (resp) {
      if (!resp.ok && resp.status !== 201) throw new Error("SB_UPSERT_" + resp.status);
      return { ok: true };
    });
  }

  /**
   * Batch upsert multiple members (used by syncFromCloud push).
   */
  function upsertMany(members) {
    if (!isConfigured()) return Promise.reject(new Error("NOT_CONFIGURED"));
    if (!members || members.length === 0) return Promise.resolve({ ok: true });

    var rows = members.map(function (m) {
      return {
        email: m.email,
        data: m,
        updated_at: new Date().toISOString()
      };
    });

    return fetch(REST_BASE + "/" + TABLE + "?on_conflict=email", {
      method: "POST",
      headers: headers({
        "Prefer": "resolution=merge-duplicates,return=minimal"
      }),
      body: JSON.stringify(rows)
    }).then(function (resp) {
      if (!resp.ok && resp.status !== 201) throw new Error("SB_BATCH_" + resp.status);
      return { ok: true };
    });
  }

  /**
   * Delete a member by email.
   */
  function deleteMember(email) {
    if (!isConfigured()) return Promise.reject(new Error("NOT_CONFIGURED"));

    return fetch(REST_BASE + "/" + TABLE + "?email=eq." + encodeURIComponent(email), {
      method: "DELETE",
      headers: headers({ "Prefer": "return=minimal" })
    }).then(function (resp) {
      if (!resp.ok) throw new Error("SB_DELETE_" + resp.status);
      return { ok: true };
    });
  }

  // ---- Export ----
  root.MFVAsupabase = {
    isConfigured: isConfigured,
    fetchMembers: fetchMembers,
    upsertMember: upsertMember,
    upsertMany: upsertMany,
    deleteMember: deleteMember
  };

})(typeof window !== "undefined" ? window : this);
