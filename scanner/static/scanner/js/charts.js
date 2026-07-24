const SEV_COLORS = {
    critical: "#f85149", high: "#ff7b39", medium: "#e3b341",
    low: "#58a6ff", info: "#8b949e",
};
const RISK_COLORS = {
    critical: "#f85149", high: "#ff7b39", medium: "#e3b341",
    low: "#58a6ff", minimal: "#56d364",
};

function _read(id) {
    const el = document.getElementById(id);
    return el ? JSON.parse(el.textContent) : {};
}

function renderDashboardCharts() {
    const sev = _read("sevData");
    const risk = _read("riskData");
    Chart.defaults.color = "#8b949e";
    Chart.defaults.borderColor = "#2a3242";

    const sevCanvas = document.getElementById("severityChart");
    if (sevCanvas) {
        const labels = ["critical", "high", "medium", "low", "info"];
        new Chart(sevCanvas, {
            type: "doughnut",
            data: {
                labels: labels.map(l => l[0].toUpperCase() + l.slice(1)),
                datasets: [{
                    data: labels.map(l => sev[l] || 0),
                    backgroundColor: labels.map(l => SEV_COLORS[l]),
                    borderColor: "#161b22", borderWidth: 2,
                }],
            },
            options: { plugins: { legend: { position: "right" } }, cutout: "62%" },
        });
    }

    const riskCanvas = document.getElementById("riskChart");
    if (riskCanvas) {
        const labels = ["critical", "high", "medium", "low", "minimal"];
        new Chart(riskCanvas, {
            type: "bar",
            data: {
                labels: labels.map(l => l[0].toUpperCase() + l.slice(1)),
                datasets: [{
                    label: "Scans",
                    data: labels.map(l => risk[l] || 0),
                    backgroundColor: labels.map(l => RISK_COLORS[l]),
                }],
            },
            options: {
                plugins: { legend: { display: false } },
                scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
            },
        });
    }
}
