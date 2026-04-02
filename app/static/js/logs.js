// Created by Anthony Kaiser
document.addEventListener("DOMContentLoaded", () => {
  const logsBody = document.getElementById("logsBody");
  const csvBtn = document.getElementById("exportCsv");
  const jsonBtn = document.getElementById("exportJson");
  const resetBtn = document.getElementById("resetLogsBtn");
  const tempUnit = (window.LOG_TEMP_UNIT || "C").toUpperCase();
  const csrfToken = window.CSRF_TOKEN || "";

  // Charts
  const ctxTemps = document.getElementById("chartTemps");
  const ctxRpmPressure = document.getElementById("chartRpmPressure");
  let chartTemps = null;
  let chartRpmPressure = null;

  const fmtTemp = (val) => {
    if (val === null || val === undefined || isNaN(val)) return "";
    let t = Number(val);
    if (tempUnit === "F") t = (t * 9 / 5) + 32;
    return t.toFixed(1);
  };

  async function fetchLogs() {
    try {
      const response = await fetch("/api/logs");
      const data = await response.json();
      const logs = Array.isArray(data) ? data : (data.logs || []);
      renderLogs(logs);
    } catch (error) {
      logsBody.innerHTML = `<tr><td colspan="6" class="text-center text-red-500 py-6">Error loading logs.</td></tr>`;
    }
  }

  function renderLogs(logs) {
    if (!logs || !logs.length) {
      logsBody.innerHTML = `<tr><td colspan="6" class="text-center text-slate-500 py-6">No logs found. Start logging from the dashboard to record data.</td></tr>`;
      clearCharts();
      return;
    }
    logsBody.innerHTML = logs.map(log => `
      <tr>
        <td class="px-4 py-2">${log.timestamp}</td>
        <td class="px-4 py-2">${fmtTemp(log.intake_temp_c)}</td>
        <td class="px-4 py-2">${fmtTemp(log.exhaust_temp_c)}</td>
        <td class="px-4 py-2">${log.rpm !== null && log.rpm !== undefined ? Math.round(Number(log.rpm)) : ""}</td>
        <td class="px-4 py-2">${log.fuel_pressure !== null && log.fuel_pressure !== undefined ? Number(log.fuel_pressure).toFixed(1) : ""}</td>
        <td class="px-4 py-2">${log.status || ""}</td>
      </tr>
    `).join("");
    updateCharts(logs);
  }

  function clearCharts() {
    if (chartTemps) { chartTemps.destroy(); chartTemps = null; }
    if (chartRpmPressure) { chartRpmPressure.destroy(); chartRpmPressure = null; }
  }

  csvBtn.addEventListener("click", () => window.location.href = "/download/logs/csv");
  jsonBtn.addEventListener("click", () => window.location.href = "/download/logs/json");

  resetBtn?.addEventListener("click", async () => {
    if (!confirm("Delete all log data? This cannot be undone.")) return;
    try {
      const res = await fetch("/api/logs/reset", {
        method: "POST",
        headers: { "X-CSRFToken": csrfToken, "X-Requested-With": "XMLHttpRequest" },
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.ok) {
        renderLogs([]);
      } else {
        alert(data.message || "Reset failed.");
      }
    } catch (e) {
      alert("Reset failed.");
    }
  });

  fetchLogs();
  setInterval(fetchLogs, 5000);

  function updateCharts(logs) {
    if (!ctxTemps || !ctxRpmPressure || !window.Chart) return;

    const ordered = [...logs].reverse();
    const labels = ordered.map(l => l.timestamp);
    const intake = ordered.map(l => fmtTemp(l.intake_temp_c));
    const exhaust = ordered.map(l => fmtTemp(l.exhaust_temp_c));
    const rpm = ordered.map(l => Number(l.rpm || 0));
    const pressure = ordered.map(l => Number(l.fuel_pressure || 0));

    clearCharts();

    chartTemps = new Chart(ctxTemps, {
      type: "line",
      data: {
        labels,
        datasets: [
          { label: `Intake (°${tempUnit})`, data: intake, borderColor: "#38bdf8", backgroundColor: "rgba(56,189,248,0.2)", tension: 0.2 },
          { label: `Exhaust (°${tempUnit})`, data: exhaust, borderColor: "#fb7185", backgroundColor: "rgba(251,113,133,0.2)", tension: 0.2 },
        ],
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: "#e2e8f0" } } },
        scales: {
          x: { ticks: { color: "#94a3b8", maxRotation: 0, autoSkip: true } },
          y: { ticks: { color: "#94a3b8" }, beginAtZero: false },
        },
      },
    });

    chartRpmPressure = new Chart(ctxRpmPressure, {
      type: "line",
      data: {
        labels,
        datasets: [
          { label: "RPM", data: rpm, yAxisID: "y", borderColor: "#a855f7", backgroundColor: "rgba(168,85,247,0.2)", tension: 0.2 },
          { label: "Fuel Pressure (PSI)", data: pressure, yAxisID: "y1", borderColor: "#f59e0b", backgroundColor: "rgba(245,158,11,0.2)", tension: 0.2 },
        ],
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: "#e2e8f0" } } },
        scales: {
          x: { ticks: { color: "#94a3b8", maxRotation: 0, autoSkip: true } },
          y: { position: "left", ticks: { color: "#c084fc" } },
          y1: { position: "right", grid: { drawOnChartArea: false }, ticks: { color: "#f59e0b" } },
        },
      },
    });
  }
});
