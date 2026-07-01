// Dashboard orchestrator. Wires the stats bar, attack map, MITRE heatmap,
// timeline, session replay, and top attackers together. Drives the 10 second
// auto-refresh polling loop and the nav bar clock and progress bar.

(function () {
  const REFRESH_SECONDS = 10;
  let countdown = REFRESH_SECONDS;

  async function fetchJSON(url) {
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(url + " -> " + res.status);
    return res.json();
  }

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function escapeAttr(s) {
    return escapeHtml(s);
  }

  // Nav bar clock. Updates every second.
  function updateClock() {
    const el = document.getElementById("nav-clock");
    if (!el) return;
    const now = new Date();
    el.textContent = now.toLocaleTimeString();
  }

  // Refresh progress bar. Fills over the refresh interval, resets on poll.
  function updateProgressBar() {
    const fill = document.getElementById("refresh-fill");
    if (!fill) return;
    const pct = ((REFRESH_SECONDS - countdown) / REFRESH_SECONDS) * 100;
    fill.style.width = pct + "%";
  }

  function markUpdated(ok) {
    const dot = document.getElementById("live-dot");
    const label = document.getElementById("live-label");
    if (dot) dot.classList.toggle("stale", !ok);
    if (label) label.textContent = ok ? "LIVE" : "STALE";
    if (ok) {
      const now = new Date();
      setText("last-updated", now.toLocaleTimeString());
    }
  }

  async function refreshStats() {
    const s = await fetchJSON("/api/stats");
    setText("stat-events", (s.events || 0).toLocaleString());
    setText("stat-attackers", (s.attackers || 0).toLocaleString());
    setText("stat-sessions", (s.sessions || 0).toLocaleString());
    setText("stat-techniques", (s.techniques || 0).toLocaleString());

    // 24h trend deltas with chip styling.
    const dEvents = document.getElementById("delta-events");
    if (dEvents) {
      const n = s.events_24h || 0;
      dEvents.innerHTML = n > 0
        ? '<span class="delta-chip delta-up">+' + n + "</span> in last 24h"
        : '<span class="delta-chip delta-flat">0</span> in last 24h';
    }
    const dAttackers = document.getElementById("delta-attackers");
    if (dAttackers) {
      const n = s.attackers_24h || 0;
      dAttackers.innerHTML = n > 0
        ? '<span class="delta-chip delta-up">+' + n + "</span> new in 24h"
        : '<span class="delta-chip delta-flat">0</span> new in 24h';
    }
  }

  async function refreshMap() {
    const rows = await fetchJSON("/api/attack-map");
    if (window.TrapHouse.map) window.TrapHouse.map.updateMap(rows);
  }

  async function refreshHeatmap() {
    const rows = await fetchJSON("/api/techniques");
    if (window.TrapHouse.heatmap) window.TrapHouse.heatmap.renderHeatmap(rows);
  }

  async function refreshTimeline() {
    const rows = await fetchJSON("/api/timeline");
    if (window.TrapHouse.timeline) window.TrapHouse.timeline.setEvents(rows);
  }

  async function refreshSessions() {
    const rows = await fetchJSON("/api/sessions");
    const select = document.getElementById("session-select");
    if (!select) return;
    const current = select.value;
    let html = '<option value="">select a session</option>';
    rows.forEach((s) => {
      const id = s.session_id || "";
      const label =
        id.slice(0, 12) +
        " | " +
        (s.source_ip || "?") +
        " | " +
        (s.event_count || 0) +
        " ev";
      const sel = id === current ? " selected" : "";
      html += '<option value="' + escapeAttr(id) + '"' + sel + ">" + escapeHtml(label) + "</option>";
    });
    select.innerHTML = html;
  }

  function riskClass(score) {
    if (score >= 18) return "risk-high";
    if (score >= 10) return "risk-med";
    return "risk-low";
  }

  function parseTechCount(mt) {
    if (!mt) return 0;
    try {
      const arr = JSON.parse(mt);
      return Array.isArray(arr) ? arr.length : 0;
    } catch (e) {
      return 0;
    }
  }

  function parseTools(td) {
    if (!td) return [];
    try {
      const arr = JSON.parse(td);
      return Array.isArray(arr) ? arr.filter((t) => t) : [];
    } catch (e) {
      return [];
    }
  }

  async function refreshAttackers() {
    const rows = await fetchJSON("/api/attackers");
    const host = document.getElementById("attacker-list");
    if (!host) return;
    const countEl = document.getElementById("attacker-count");
    if (countEl) countEl.textContent = rows.length;

    if (!rows || rows.length === 0) {
      host.innerHTML = '<div class="replay-empty">No attacker profiles yet.</div>';
      return;
    }
    const top = rows.slice(0, 10);
    const maxRisk = Math.max.apply(null, top.map((a) => a.risk_score || 0));
    let html = "";
    top.forEach((a, i) => {
      const ip = a.source_ip || "?";
      const risk = a.risk_score || 0;
      const events = a.event_count || 0;
      const sessions = a.session_count || 0;
      const user = a.top_username || "";
      const techCount = parseTechCount(a.mitre_techniques);
      const tools = parseTools(a.tools_detected);
      const rc = riskClass(risk);
      const barPct = maxRisk > 0 ? Math.round((risk / maxRisk) * 100) : 0;
      const userHtml = user
        ? '<span class="attacker-user">' + escapeHtml(user) + "</span>"
        : '<span class="attacker-user attacker-user-empty">none</span>';

      let intelHtml = "";
      if (techCount > 0) {
        intelHtml += '<span class="intel-badge intel-mitre">' + techCount + " MITRE</span>";
      }
      tools.forEach((t) => {
        intelHtml += '<span class="intel-badge intel-tool">' + escapeHtml(t) + "</span>";
      });
      if (!intelHtml) intelHtml = '<span class="intel-badge">none</span>';

      html +=
        '<div class="attacker-row" data-ip="' + escapeAttr(ip) + '">' +
        '<span><span class="attacker-rank">' + (i + 1) + "</span>" +
        '<span class="attacker-ip">' + escapeHtml(ip) + "</span></span>" +
        '<span class="attacker-riskcell">' +
        '<span class="attacker-risk ' + rc + '">' + risk.toFixed(1) + "</span>" +
        '<span class="risk-bar"><span class="risk-bar-fill ' + rc + '" style="width:' + barPct + '%"></span></span>' +
        "</span>" +
        '<span class="attacker-num">' + events + "</span>" +
        '<span class="attacker-num">' + sessions + "</span>" +
        userHtml +
        '<span class="attacker-intel">' + intelHtml + "</span>" +
        "</div>";
    });
    host.innerHTML = html;

    host.querySelectorAll(".attacker-row").forEach((row) => {
      row.addEventListener("click", function () {
        const ip = this.getAttribute("data-ip");
        const filter = document.getElementById("filter-sourceip");
        if (filter) {
          filter.value = ip;
          filter.dispatchEvent(new Event("change"));
        }
      });
    });
  }

  async function loadSession(sessionId) {
    if (!sessionId) {
      if (window.TrapHouse.replay) window.TrapHouse.replay.showEmpty();
      return;
    }
    const events = await fetchJSON("/api/sessions/" + encodeURIComponent(sessionId) + "/events");
    if (window.TrapHouse.replay) window.TrapHouse.replay.renderReplay(events);
  }

  async function refreshAll() {
    try {
      await Promise.all([
        refreshStats(),
        refreshMap(),
        refreshHeatmap(),
        refreshTimeline(),
        refreshSessions(),
        refreshAttackers(),
      ]);
      markUpdated(true);
    } catch (err) {
      console.error("refresh failed", err);
      markUpdated(false);
    }
  }

  function tickCountdown() {
    countdown -= 1;
    if (countdown <= 0) {
      countdown = REFRESH_SECONDS;
      refreshAll();
    }
    setText("refresh-countdown", countdown);
    updateProgressBar();
  }

  function init() {
    if (window.TrapHouse.map) window.TrapHouse.map.initMap();
    if (window.TrapHouse.timeline) window.TrapHouse.timeline.initFilters();

    const select = document.getElementById("session-select");
    if (select) {
      select.addEventListener("change", function () {
        loadSession(this.value);
      });
    }

    updateClock();
    setInterval(updateClock, 1000);
    refreshAll();
    setInterval(tickCountdown, 1000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();