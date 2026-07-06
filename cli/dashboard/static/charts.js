"use strict";

// DampingCharts: small, dependency-free chart primitives shared by
// index.html's stats panel and recent-sessions sparklines. Every element is
// built via DOM/SVG-namespace APIs (createElement/createElementNS +
// textContent), never innerHTML or string interpolation — event-derived
// fields (rule ids come from a locally-authored policy.yaml, but this stays
// consistent with the same rule index.html's renderRow/renderDetail already
// follow for genuinely attacker-influenced fields like Target/Raw) never
// need a second escaping pass because they're never parsed as markup here.
const DampingCharts = (() => {
  const RISK_COLORS = { low: "#14b8a6", medium: "#eab308", high: "#f59e0b", critical: "#ef4444" };
  const svgNS = "http://www.w3.org/2000/svg";

  // sparkline renders points (small integers, risk level per event in
  // chronological order) as a single polyline — moved here verbatim from
  // index.html's original renderSparkline so recent-sessions cards and the
  // stats panel share one implementation.
  function sparkline(svg, points) {
    svg.textContent = "";
    if (points.length === 0) {
      const line = document.createElementNS(svgNS, "line");
      line.setAttribute("x1", "0"); line.setAttribute("y1", "20"); line.setAttribute("x2", "100"); line.setAttribute("y2", "20");
      line.setAttribute("stroke", "#14b8a6"); line.setAttribute("stroke-width", "2");
      svg.appendChild(line);
      return;
    }
    const max = 4, w = 100, h = 24, pad = 3;
    const step = points.length > 1 ? w / (points.length - 1) : 0;
    const coords = points.map((p, i) => {
      const x = points.length > 1 ? i * step : w / 2;
      const y = h - pad - (p - 1) / (max - 1) * (h - 2 * pad);
      return [x, y];
    });
    const path = document.createElementNS(svgNS, "polyline");
    path.setAttribute("points", coords.map(c => c[0].toFixed(1) + "," + c[1].toFixed(1)).join(" "));
    path.setAttribute("fill", "none");
    path.setAttribute("stroke-width", "2");
    const lastRisk = points[points.length - 1];
    path.setAttribute("stroke", lastRisk >= 3 ? "#f59e0b" : lastRisk === 2 ? "#eab308" : "#14b8a6");
    svg.appendChild(path);
  }

  // stackedRiskOverTime renders /api/stats's risk_over_time buckets as a
  // stacked bar chart (low/medium/high/critical counts per time slice,
  // bottom-up) — one <g> per bucket with a <title> tooltip summarizing it,
  // since a plain SVG chart has nothing else for a mouse/screen-reader user
  // to inspect a specific bar's exact counts with.
  function stackedRiskOverTime(svg, buckets) {
    svg.textContent = "";
    const w = 400, h = 120, gap = 2;
    svg.setAttribute("viewBox", "0 0 " + w + " " + h);
    if (!buckets || buckets.length === 0) return;

    const totals = buckets.map(b => (b.low || 0) + (b.medium || 0) + (b.high || 0) + (b.critical || 0));
    const maxTotal = Math.max(1, ...totals);
    const barW = w / buckets.length;

    buckets.forEach((b, i) => {
      const g = document.createElementNS(svgNS, "g");
      const title = document.createElementNS(svgNS, "title");
      const when = new Date(b.bucket_start);
      const whenLabel = isNaN(when) ? b.bucket_start : when.toLocaleString(undefined, { hour12: false });
      title.textContent = whenLabel + ": " + totals[i] + " event(s) (low " + (b.low || 0) + ", medium " + (b.medium || 0) + ", high " + (b.high || 0) + ", critical " + (b.critical || 0) + ")";
      g.appendChild(title);

      let yCursor = h;
      for (const tier of ["low", "medium", "high", "critical"]) {
        const count = b[tier] || 0;
        if (count === 0) continue;
        const barH = (count / maxTotal) * h;
        const rect = document.createElementNS(svgNS, "rect");
        rect.setAttribute("x", (i * barW + gap / 2).toFixed(1));
        rect.setAttribute("width", Math.max(0, barW - gap).toFixed(1));
        rect.setAttribute("y", (yCursor - barH).toFixed(1));
        rect.setAttribute("height", barH.toFixed(1));
        rect.setAttribute("fill", RISK_COLORS[tier]);
        g.appendChild(rect);
        yCursor -= barH;
      }
      svg.appendChild(g);
    });
  }

  // barChart renders items ([{label, count}], already sorted by the caller)
  // as horizontal bar rows appended to container — plain HTML elements
  // (a styled div per bar), not SVG, since a proportional-width div is
  // simpler and more legible for a labeled list than sizing SVG <text>.
  function barChart(container, items) {
    container.textContent = "";
    if (!items || items.length === 0) return;
    const maxCount = Math.max(1, ...items.map(it => it.count));
    for (const it of items) {
      const row = document.createElement("div");
      row.className = "bar-row";

      const label = document.createElement("span");
      label.className = "bar-label";
      label.textContent = it.label;
      label.title = it.label;

      const track = document.createElement("div");
      track.className = "bar-track";
      const fill = document.createElement("div");
      fill.className = "bar-fill";
      fill.style.width = Math.max(2, (it.count / maxCount) * 100) + "%";
      if (it.color) fill.style.backgroundColor = it.color;
      track.appendChild(fill);

      const count = document.createElement("span");
      count.className = "bar-count";
      count.textContent = String(it.count);

      row.appendChild(label);
      row.appendChild(track);
      row.appendChild(count);
      container.appendChild(row);
    }
  }

  return { sparkline, stackedRiskOverTime, barChart, RISK_COLORS };
})();
