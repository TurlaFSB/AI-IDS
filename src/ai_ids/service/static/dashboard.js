"use strict";
// Every value is rendered with textContent, so data from alerts cannot inject markup.
(function () {
  const POLL_MS = 1500;
  const $ = (id) => document.getElementById(id);
  let key = sessionStorage.getItem("ai-ids-read-key") || "";

  // A key can be passed in the URL fragment (#key=...); fragments are never sent to the server.
  const fromHash = new URLSearchParams(location.hash.slice(1)).get("key");
  if (fromHash) {
    key = fromHash;
    sessionStorage.setItem("ai-ids-read-key", key);
    history.replaceState(null, "", location.pathname + location.search);
  }

  function setStatus(text, cls) {
    const pill = $("status");
    pill.textContent = text;
    pill.className = "pill " + (cls || "");
  }

  function askForKey() {
    const dialog = $("login");
    if (typeof dialog.showModal === "function" && !dialog.open) dialog.showModal();
  }

  async function get(path) {
    const response = await fetch(path, { headers: { Authorization: "Bearer " + key } });
    if (response.status === 401) { key = ""; sessionStorage.removeItem("ai-ids-read-key"); askForKey(); throw new Error("unauthorized"); }
    if (!response.ok) throw new Error("HTTP " + response.status);
    return response.json();
  }

  function fmt(value) { return typeof value === "number" ? value.toLocaleString() : "n/a"; }
  function ms(value) { return typeof value === "number" ? value.toFixed(1) : "n/a"; }

  function drawChart(series) {
    const canvas = $("chart"); const ctx = canvas.getContext("2d");
    const style = getComputedStyle(document.documentElement);
    const flowsColor = style.getPropertyValue("--flows").trim();
    const alertsColor = style.getPropertyValue("--alerts").trim();
    const lineColor = style.getPropertyValue("--line").trim();
    const w = canvas.width, h = canvas.height, pad = 8;
    ctx.clearRect(0, 0, w, h);
    const maxFlows = Math.max(1, ...series.map((p) => p.flows));
    const barW = (w - 2 * pad) / series.length;
    ctx.strokeStyle = lineColor; ctx.beginPath(); ctx.moveTo(pad, h - pad); ctx.lineTo(w - pad, h - pad); ctx.stroke();
    series.forEach((p, i) => {
      const x = pad + i * barW;
      const hf = ((h - 2 * pad) * p.flows) / maxFlows;
      ctx.fillStyle = flowsColor; ctx.fillRect(x + 1, h - pad - hf, Math.max(1, barW - 2), hf);
      const ha = Math.min(hf, ((h - 2 * pad) * p.alerts) / maxFlows);
      ctx.fillStyle = alertsColor; ctx.fillRect(x + 1, h - pad - ha, Math.max(1, barW - 2), ha);
    });
  }

  function cell(row, text) {
    const td = document.createElement("td");
    td.textContent = text === undefined || text === null ? "" : String(text);
    row.appendChild(td);
  }

  function renderAlerts(alerts) {
    const body = $("alert-rows");
    body.replaceChildren();
    alerts.forEach((a) => {
      const tr = document.createElement("tr");
      cell(tr, a.time ? a.time.replace("T", " ").replace("+00:00", "") : "");
      cell(tr, a.source_ip); cell(tr, a.destination_ip); cell(tr, a.destination_port);
      cell(tr, typeof a.score === "number" ? a.score.toFixed(3) : "");
      cell(tr, a.category); cell(tr, (a.attack_techniques || []).join(", "));
      body.appendChild(tr);
    });
  }

  async function refresh() {
    if (!key) { askForKey(); return; }
    try {
      const [stats, recent] = await Promise.all([get("/v1/stats"), get("/v1/alerts?limit=25")]);
      $("model").textContent = stats.model.detector + "  |  threshold " + Number(stats.model.threshold).toPrecision(4);
      $("flows").textContent = fmt(stats.flows_scored);
      $("alerts-total").textContent = fmt(stats.alerts_raised);
      const perMinute = Math.round(60 / stats.bucket_seconds);
      const recentAlerts = stats.series.slice(-perMinute).reduce((sum, p) => sum + p.alerts, 0);
      $("alerts-minute").textContent = fmt(recentAlerts);
      $("latency").textContent = ms(stats.request_latency_ms.p50) + " / " + ms(stats.request_latency_ms.p95) + " ms";
      drawChart(stats.series);
      renderAlerts(recent.alerts);
      setStatus("live", "ok");
    } catch (error) {
      if (String(error.message) !== "unauthorized") setStatus("connection problem", "bad");
    }
  }

  $("login-form").addEventListener("submit", () => {
    key = $("key").value.trim();
    if (key) { sessionStorage.setItem("ai-ids-read-key", key); $("key").value = ""; refresh(); }
  });

  refresh();
  setInterval(refresh, POLL_MS);
})();
