// Attack map: Leaflet with CartoDB Dark Matter tiles. Markers colored by risk,
// sized by attack count, popups with IP details. Geolocation is deterministic
// client-side since dev source IPs are internal Docker addresses.

window.TrapHouse = window.TrapHouse || {};

(function () {
  let map = null;
  let layerGroup = null;

  // Deterministic pseudo-geolocation: hash an IP string to a stable lat/lng so
  // markers spread across the map instead of all stacking at one point. In
  // production a real geolocation lookup would replace this; the dashboard note
  // explains that dev shows internal Docker IPs.
  function ipToLatLng(ip) {
    let h1 = 2166136261;
    let h2 = 5381;
    for (let i = 0; i < ip.length; i++) {
      const c = ip.charCodeAt(i);
      h1 = (h1 ^ c) * 16777619;
      h2 = (h2 * 33) ^ c;
    }
    const lat = (Math.abs(h1) % 12000) / 100 - 58; // range roughly -58 .. 62
    const lng = (Math.abs(h2) % 34000) / 100 - 170; // range roughly -170 .. 170
    return [lat, lng];
  }

  function riskColor(risk) {
    if (risk >= 30) return "#ff4444";
    if (risk >= 15) return "#f5d142";
    return "#22c55e";
  }

  function radiusFor(attacks) {
    return Math.min(6 + Math.sqrt(attacks) * 2.5, 26);
  }

  function topTechniques(raw) {
    if (!raw) return "none";
    const parts = String(raw)
      .replace(/[\[\]"']/g, "")
      .split(/[,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (!parts.length) return "none";
    return parts.slice(0, 5).join(", ");
  }

  function initMap() {
    if (map) return;
    map = L.map("attack-map", {
      worldCopyJump: true,
      minZoom: 1,
      attributionControl: true,
    }).setView([25, 10], 2);

    L.tileLayer(
      "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
      {
        maxZoom: 19,
        attribution:
          '&copy; OpenStreetMap &copy; CARTO',
        subdomains: "abcd",
      }
    ).addTo(map);

    layerGroup = L.layerGroup().addTo(map);
  }

  function updateMap(rows) {
    if (!map) initMap();
    layerGroup.clearLayers();
    if (!Array.isArray(rows)) return;

    rows.forEach((row) => {
      const ip = row.source_ip || "";
      if (!ip) return;
      const attacks = row.attacks || 0;
      const risk = row.risk_score || 0;
      const [lat, lng] = ipToLatLng(ip);
      const color = riskColor(risk);

      const marker = L.circleMarker([lat, lng], {
        radius: radiusFor(attacks),
        color: color,
        weight: 1.5,
        fillColor: color,
        fillOpacity: 0.55,
      });

      const riskClass = risk >= 30 ? "map-popup-risk-high" : "map-popup-row";
      marker.bindPopup(
        '<div class="map-popup">' +
          '<div class="map-popup-ip">' + escapeHtml(ip) + "</div>" +
          '<div class="map-popup-row">events: ' + attacks + "</div>" +
          '<div class="' + riskClass + '">risk: ' + Number(risk).toFixed(1) + "</div>" +
          '<div class="map-popup-row">techniques: ' + escapeHtml(topTechniques(row.mitre_techniques)) + "</div>" +
          "</div>"
      );
      marker.addTo(layerGroup);
    });
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  window.TrapHouse.map = { initMap, updateMap };
})();
