// Dashboard orchestrator. Wires the stats bar, attack map, MITRE heatmap,
// timeline, and session replay together and drives the 10 second auto-refresh
// polling loop. All other modules attach to window.TrapHouse.

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

    // 24h trend deltas
    const dEvents = document.getElementById("delta-events");
    if (dEvents) {
      const n = s.events_24h || 0;
      dEvents.innerHTML = n > 0
        ? '<span class="delta-up">+' + n + '</span> in last 24h'
        : '<span class="delta-flat">0 in last 24h</span>';
    }
    const dAttackers = document.getElementById("delta-attackers");
    if (dAttackers) {
      const n = s.attackers_24h || 0;
      dAttackers.innerHTML = n > 0
        ? '<span class="delta-up">+' + n + '</span> new in 24h'
        : '<span class="delta-flat">0 new in 24h</span>';
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

  async function refreshAttackers() {
    const rows = await fetchJSON("/api/attackers");
    const host = document.getElementById("attacker-list");
    if (!host) return;
    if (!rows || rows.length === 0) {
      host.innerHTML = '<div class="replay-empty">No attacker profiles yet.</div>';
      return;
    }
    const top = rows.slice(0, 10);
    let html = "";
    top.forEach((a) => {
      const ip = a.source_ip || "?";
      const risk = a.risk_score || 0;
      const events = a.event_count || 0;
      const sessions = a.session_count || 0;
      const user = a.top_username || "";
      const techCount = a.mitre_techniques
        ? (a.mitre_techniques.match(/"/g) || []).length / 2
        : 0;
      html +=
        '<div class="attacker-row" data-ip="' + escapeAttr(ip) + '">' +
        '<span class="attacker-ip">' + escapeHtml(ip) + "</span>" +
        '<span class="attacker-meta">' + events + " ev / " + sessions + " sess / " + Math.round(techCount) + " MITRE</span>" +
        '<span class="attacker-user">' + escapeHtml(user) + "</span>" +
        '<span class="attacker-risk ' + riskClass(risk) + '">' + risk.toFixed(1) + "</span>" +
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

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function escapeAttr(s) {
    return escapeHtml(s);
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

    refreshAll();
    setInterval(tickCountdown, 1000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
