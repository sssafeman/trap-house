// Session replay. Renders a vertical timeline of a single session's events as
// cards, color-coded by the deception layer the attacker reached:
// SSH -> Web Login -> Dashboard -> SQL Injection -> Webshell -> Config.

window.TrapHouse = window.TrapHouse || {};

(function () {
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // Classify an event into a deception layer for color coding.
  function layerFor(event) {
    const svc = (event.source_service || "").toLowerCase();
    const type = (event.event_type || "").toLowerCase();
    const cmd = (event.command || "").toLowerCase();

    if (type.includes("config") || cmd.includes("config")) return "config";
    if (type.includes("webshell") || type.includes("shell") || cmd.includes("webshell")) return "shell";
    if (type.includes("sqli") || type.includes("sql_injection") || type.includes("injection")) return "sqli";
    if (svc === "cowrie" || svc === "endlessh" || type.includes("ssh") || type.includes("login")) {
      // Web login events carry a deception-gw service even when typed "login".
      if (svc === "deception-gw" && type.includes("login")) return "web";
      return "ssh";
    }
    if (svc === "deception-gw" || type.includes("web") || type.includes("http")) return "web";
    return "ssh";
  }

  const LEGEND = [
    { layer: "ssh", color: "var(--layer-ssh)", label: "SSH" },
    { layer: "web", color: "var(--layer-web)", label: "Web Login" },
    { layer: "sqli", color: "var(--layer-sqli)", label: "SQL Injection" },
    { layer: "shell", color: "var(--layer-shell)", label: "Webshell" },
    { layer: "config", color: "var(--layer-config)", label: "Config" },
  ];

  function legendHtml() {
    let h = '<div class="layer-legend">';
    LEGEND.forEach((l) => {
      h +=
        "<span><span class=\"legend-swatch\" style=\"background:" + l.color + "\"></span>" +
        l.label + "</span>";
    });
    return h + "</div>";
  }

  function renderReplay(events) {
    const host = document.getElementById("session-replay");
    if (!host) return;
    if (!Array.isArray(events) || events.length === 0) {
      host.innerHTML = '<div class="replay-empty">No events recorded for this session.</div>';
      return;
    }

    let html = legendHtml();
    events.forEach((ev) => {
      const layer = layerFor(ev);
      const time = ev.timestamp ? escapeHtml(ev.timestamp) : "";
      const type = escapeHtml(ev.event_type || "event");
      const svc = escapeHtml(ev.source_service || "");
      const user = ev.username ? '<div class="replay-meta">user: ' + escapeHtml(ev.username) + "</div>" : "";
      const cmd = ev.command ? '<div class="replay-cmd">' + escapeHtml(ev.command) + "</div>" : "";
      const tech = ev.mitre_technique
        ? '<div class="replay-tech">MITRE: ' + escapeHtml(ev.mitre_technique) + "</div>"
        : "";
      html +=
        '<div class="replay-step layer-' + layer + '">' +
        '<div class="replay-card">' +
        '<div class="replay-time">' + time + " &middot; " + svc + "</div>" +
        '<div class="replay-type">' + type + "</div>" +
        user +
        cmd +
        tech +
        "</div></div>";
    });

    host.innerHTML = html;
  }

  function showEmpty() {
    const host = document.getElementById("session-replay");
    if (host) {
      host.innerHTML =
        '<div class="replay-empty">Select a session to replay attacker progression through the deception layers.</div>';
    }
  }

  window.TrapHouse.replay = { renderReplay, showEmpty };
})();
