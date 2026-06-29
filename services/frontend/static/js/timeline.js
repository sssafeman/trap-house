// Attack timeline. Horizontal scrolling row of colored dots, one per recent
// event, colored by source service. Hover shows details. A filter bar narrows
// by service, event type, and source IP. The MITRE heatmap can also push a
// technique filter in via filterByTechnique.

window.TrapHouse = window.TrapHouse || {};

(function () {
  let allEvents = [];
  let techniqueFilter = null;

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function serviceClass(svc) {
    const s = (svc || "").toLowerCase();
    if (s === "cowrie") return "svc-cowrie";
    if (s === "deception-gw") return "svc-deception-gw";
    if (s === "endlessh") return "svc-endlessh";
    return "svc-other";
  }

  function currentFilters() {
    return {
      service: valueOf("filter-service"),
      eventType: valueOf("filter-eventtype"),
      sourceIp: valueOf("filter-sourceip"),
    };
  }

  function valueOf(id) {
    const el = document.getElementById(id);
    return el ? el.value : "";
  }

  function applyFilters(events) {
    const f = currentFilters();
    return events.filter((ev) => {
      if (f.service && ev.source_service !== f.service) return false;
      if (f.eventType && ev.event_type !== f.eventType) return false;
      if (f.sourceIp && ev.source_ip !== f.sourceIp) return false;
      if (techniqueFilter && ev.mitre_technique !== techniqueFilter) return false;
      return true;
    });
  }

  // Populate the filter dropdowns from the data, preserving the current choice.
  function rebuildFilterOptions() {
    const services = new Set();
    const types = new Set();
    const ips = new Set();
    allEvents.forEach((ev) => {
      if (ev.source_service) services.add(ev.source_service);
      if (ev.event_type) types.add(ev.event_type);
      if (ev.source_ip) ips.add(ev.source_ip);
    });
    fillSelect("filter-service", services, "all services");
    fillSelect("filter-eventtype", types, "all event types");
    fillSelect("filter-sourceip", ips, "all source IPs");
  }

  function fillSelect(id, valueSet, allLabel) {
    const el = document.getElementById(id);
    if (!el) return;
    const current = el.value;
    const values = Array.from(valueSet).sort();
    let html = '<option value="">' + allLabel + "</option>";
    values.forEach((v) => {
      const sel = v === current ? " selected" : "";
      html += '<option value="' + escapeHtml(v) + '"' + sel + ">" + escapeHtml(v) + "</option>";
    });
    el.innerHTML = html;
  }

  function render() {
    const host = document.getElementById("timeline");
    if (!host) return;
    // API returns newest first. Show oldest -> newest left to right so new
    // events arrive on the right edge.
    const events = applyFilters(allEvents).slice().reverse();
    if (events.length === 0) {
      host.innerHTML = '<span class="panel-note">No events match the current filters.</span>';
      return;
    }
    let html = "";
    events.forEach((ev, i) => {
      html +=
        '<div class="timeline-dot ' + serviceClass(ev.source_service) + '" data-idx="' + i + '"></div>';
    });
    host.innerHTML = html;

    const ordered = events;
    host.querySelectorAll(".timeline-dot").forEach((dot) => {
      dot.addEventListener("mouseenter", function () {
        const ev = ordered[parseInt(this.getAttribute("data-idx"), 10)];
        showDetail(ev);
      });
    });
    host.scrollLeft = host.scrollWidth;
  }

  function showDetail(ev) {
    const host = document.getElementById("timeline-detail");
    if (!host || !ev) return;
    const parts = [
      ev.timestamp || "",
      ev.source_service || "",
      ev.event_type || "",
      ev.source_ip || "",
    ];
    if (ev.mitre_technique) parts.push("MITRE " + ev.mitre_technique);
    if (ev.command) parts.push("cmd: " + ev.command);
    host.textContent = parts.filter(Boolean).join("  |  ");
  }

  function setEvents(events) {
    allEvents = Array.isArray(events) ? events : [];
    rebuildFilterOptions();
    render();
  }

  function filterByTechnique(techniqueId) {
    techniqueFilter = techniqueId || null;
    const note = document.getElementById("heatmap-filter-note");
    if (note) {
      note.textContent = techniqueFilter
        ? "Timeline filtered to " + techniqueFilter + ". Click again to clear."
        : "Click a technique to filter the timeline.";
    }
    render();
  }

  function initFilters() {
    ["filter-service", "filter-eventtype", "filter-sourceip"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", render);
    });
    const clear = document.getElementById("filter-clear");
    if (clear) {
      clear.addEventListener("click", function () {
        ["filter-service", "filter-eventtype", "filter-sourceip"].forEach((id) => {
          const el = document.getElementById(id);
          if (el) el.value = "";
        });
        techniqueFilter = null;
        const note = document.getElementById("heatmap-filter-note");
        if (note) note.textContent = "Click a technique to filter the timeline.";
        render();
      });
    }
  }

  window.TrapHouse.timeline = { setEvents, filterByTechnique, initFilters };
})();
