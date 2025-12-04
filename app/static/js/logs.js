// Created by Anthony Kaiser
document.addEventListener("DOMContentLoaded", () => {
  const logsBody = document.getElementById("logsBody");
  const csvBtn = document.getElementById("exportCsv");
  const jsonBtn = document.getElementById("exportJson");
  const tempUnit = (window.LOG_TEMP_UNIT || "C").toUpperCase();

  // Charts
  const ctxTemps = document.getElementById("chartTemps");
  const ctxRpmThrust = document.getElementById("chartRpmThrust");
  let chartTemps = null;
  let chartRpmThrust = null;

  const fmtTemp = (val) => {
    if (val === null || val === undefined || isNaN(val)) return "";
    let t = Number(val);
    if (tempUnit === "F") {
      t = (t * 9/5) + 32;
    }
    return t.toFixed(1);
  };

  async function fetchLogs() {
    try {
      const response = await fetch("/api/logs");
      const data = await response.json();
      renderLogs(data);
    } catch (error) {
      logsBody.innerHTML = `<tr><td colspan="7" class="text-center text-red-500 py-6">Error loading logs.</td></tr>`;
    }
  }

  function renderLogs(logs) {
    if (!logs || !logs.length) {
      // Show a fake sample row so UI has content
      logs = [{
        timestamp: new Date().toISOString().slice(0, 19).replace("T", " "),
        intake_temp_c: 32.5,
        exhaust_temp_c: 285.0,
        rpm: 42000,
        thrust_n: 12.4,
        fuel_flow_kg_s: 0.14,
        status: "sample"
      }];
    }
    if (!logs.length) {
      logsBody.innerHTML = `<tr><td colspan="7" class="text-center text-slate-500 py-6">No logs found.</td></tr>`;
      updateCharts([]);
      return;
    }
    logsBody.innerHTML = logs.map(log => `
      <tr>
        <td class="px-4 py-2">${log.timestamp}</td>
        <td class="px-4 py-2">${fmtTemp(log.intake_temp_c)}</td>
        <td class="px-4 py-2">${fmtTemp(log.exhaust_temp_c)}</td>
        <td class="px-4 py-2">${log.rpm}</td>
        <td class="px-4 py-2">${log.thrust_n}</td>
        <td class="px-4 py-2">${log.fuel_flow_kg_s}</td>
        <td class="px-4 py-2">${log.status}</td>
      </tr>
    `).join("");
    updateCharts(logs);
  }

  csvBtn.addEventListener("click", () => window.location.href = "/download/logs/csv");
  jsonBtn.addEventListener("click", () => window.location.href = "/download/logs/json");

  fetchLogs();
  setInterval(fetchLogs, 5000); // refresh every 5s

  function updateCharts(logs) {
    if (!ctxTemps || !ctxRpmThrust || !window.Chart) return;

    const labels = logs.map(l => l.timestamp).reverse();
    const intake = logs.map(l => fmtTemp(l.intake_temp_c)).reverse();
    const exhaust = logs.map(l => fmtTemp(l.exhaust_temp_c)).reverse();
    const rpm = logs.map(l => Number(l.rpm || 0)).reverse();
    const thrust = logs.map(l => Number(l.thrust_n || 0)).reverse();

    if (chartTemps) chartTemps.destroy();
    if (chartRpmThrust) chartRpmThrust.destroy();

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

    chartRpmThrust = new Chart(ctxRpmThrust, {
      type: "line",
      data: {
        labels,
        datasets: [
          { label: "RPM", data: rpm, yAxisID: "y", borderColor: "#a855f7", backgroundColor: "rgba(168,85,247,0.2)", tension: 0.2 },
          { label: "Thrust (N)", data: thrust, yAxisID: "y1", borderColor: "#22c55e", backgroundColor: "rgba(34,197,94,0.2)", tension: 0.2 },
        ],
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: "#e2e8f0" } } },
        scales: {
          x: { ticks: { color: "#94a3b8", maxRotation: 0, autoSkip: true } },
          y: { position: "left", ticks: { color: "#c084fc" } },
          y1: { position: "right", grid: { drawOnChartArea: false }, ticks: { color: "#4ade80" } },
        },
      },
    });
  }
});
