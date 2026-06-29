// MITRE ATT&CK heatmap. Rows are tactics, cells are techniques. Cell color
// intensity scales with event frequency. Clicking a cell filters the timeline
// to that technique.

window.TrapHouse = window.TrapHouse || {};

(function () {
  // Tactic order for the heatmap rows. Matches the deception kill chain.
  const TACTIC_ORDER = [
    "reconnaissance",
    "initial-access",
    "execution",
    "persistence",
    "credential-access",
    "discovery",
    "command-and-control",
    "lateral-movement",
    "defense-evasion",
  ];

  let activeTechnique = null;

  function normTactic(tactic) {
    return String(tactic || "")
      .trim()
      .toLowerCase()
      .replace(/[\s_]+/g, "-");
  }

  // Map a 0..1 intensity onto the cyan accent so busier techniques glow brighter.
  function cellStyle(count, maxCount) {
    const t = maxCount > 0 ? count / maxCount : 0;
    const alpha = 0.12 + t * 0.78;
    return "background: rgba(0, 212, 255, " + alpha.toFixed(2) + ");";
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function renderHeatmap(rows) {
    const host = document.getElementById("mitre-heatmap");
    if (!host) return;
    if (!Array.isArray(rows) || rows.length === 0) {
      host.innerHTML = '<div class="heatmap-empty">No techniques recorded yet.</div>';
      return;
    }

    // Group techniques under their tactic. Unknown tactics fall into "other".
    const byTactic = {};
    let maxCount = 0;
    rows.forEach((r) => {
      const tactic = normTactic(r.tactic) || "other";
      if (!byTactic[tactic]) byTactic[tactic] = [];
      byTactic[tactic].push(r);
      if (r.count > maxCount) maxCount = r.count;
    });

    const tactics = TACTIC_ORDER.filter((t) => byTactic[t]);
    Object.keys(byTactic).forEach((t) => {
      if (!tactics.includes(t)) tactics.push(t);
    });

    let html = "";
    tactics.forEach((tactic) => {
      const cells = byTactic[tactic]
        .slice()
        .sort((a, b) => b.count - a.count);
      let cellsHtml = "";
      cells.forEach((c) => {
        const tid = c.technique_id || "";
        const active = tid === activeTechnique ? " active" : "";
        const label = c.name ? tid + " " + c.name : tid;
        cellsHtml +=
          '<div class="heatmap-cell' + active + '" ' +
          'style="' + cellStyle(c.count, maxCount) + '" ' +
          'data-technique="' + escapeHtml(tid) + '" ' +
          'title="' + escapeHtml(label) + ' (' + c.count + ' events)">' +
          escapeHtml(tid) +
          '<span class="cell-count">' + c.count + "</span>" +
          "</div>";
      });
      html +=
        '<div class="heatmap-tactic-row">' +
        '<div class="heatmap-tactic-label">' + escapeHtml(tactic.replace(/-/g, " ")) + "</div>" +
        '<div class="heatmap-cells">' + cellsHtml + "</div>" +
        "</div>";
    });

    host.innerHTML = html;

    host.querySelectorAll(".heatmap-cell").forEach((cell) => {
      cell.addEventListener("click", function () {
        const tid = this.getAttribute("data-technique");
        activeTechnique = activeTechnique === tid ? null : tid;
        renderHeatmap(rows);
        if (window.TrapHouse.timeline && window.TrapHouse.timeline.filterByTechnique) {
          window.TrapHouse.timeline.filterByTechnique(activeTechnique);
        }
      });
    });
  }

  window.TrapHouse.heatmap = { renderHeatmap };
})();
