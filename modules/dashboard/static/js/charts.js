/**
 * PDR Dashboard — charts.js
 * Chart factory functions. All use Chart.js globals already loaded by base.html.
 */

const PDR_COLORS = {
    cyan:   '#00d4ff',
    green:  '#2ed573',
    amber:  '#ffa502',
    purple: '#a29bfe',
    red:    '#ff4757',
    coral:  '#fd9644',
    palette: ['#00d4ff','#2ed573','#ffa502','#a29bfe','#ff4757','#fd9644']
};

const PDR_CHART_DEFAULTS = {
    font:        'JetBrains Mono',
    gridColor:   'rgba(0,212,255,.05)',
    textColor:   '#8899bb',
    borderColor: '#0f1a28'
};

/* Apply global Chart.js defaults once */
(function applyDefaults() {
    if (typeof Chart === 'undefined') return;
    Chart.defaults.color       = PDR_CHART_DEFAULTS.textColor;
    Chart.defaults.font.family = PDR_CHART_DEFAULTS.font;
    Chart.defaults.font.size   = 11;
})();

/**
 * Line chart for traffic timelines
 */
function createTimelineChart(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels || [],
            datasets: [{
                label: 'Packets',
                data: data.packets || data.values || [],
                borderColor: PDR_COLORS.cyan,
                backgroundColor: 'rgba(0,212,255,.06)',
                borderWidth: 1.5,
                fill: true,
                tension: .4,
                pointRadius: 2,
                pointBackgroundColor: PDR_COLORS.cyan
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: PDR_CHART_DEFAULTS.gridColor }, ticks: { font: { family: PDR_CHART_DEFAULTS.font, size: 10 } } },
                y: { grid: { color: PDR_CHART_DEFAULTS.gridColor }, ticks: { font: { family: PDR_CHART_DEFAULTS.font, size: 10 } }, beginAtZero: true }
            }
        }
    });
}

/**
 * Doughnut chart for protocol distribution
 */
function createProtocolChart(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.labels || [],
            datasets: [{
                data: data.values || [],
                backgroundColor: PDR_COLORS.palette,
                borderColor: PDR_CHART_DEFAULTS.borderColor,
                borderWidth: 2,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '68%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: PDR_CHART_DEFAULTS.textColor,
                        font: { family: PDR_CHART_DEFAULTS.font, size: 11 },
                        boxWidth: 10,
                        padding: 12
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function (ctx) {
                            const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                            const pct   = ((ctx.raw / total) * 100).toFixed(1);
                            return ' ' + ctx.label + ': ' + ctx.raw + ' (' + pct + '%)';
                        }
                    }
                }
            }
        }
    });
}

/**
 * Stacked bar chart for alerts by severity over time
 */
function createAlertsChart(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.labels || [],
            datasets: [
                { label: 'High',   data: data.high   || [], backgroundColor: PDR_COLORS.red,   stack: 'alerts' },
                { label: 'Medium', data: data.medium || [], backgroundColor: PDR_COLORS.amber,  stack: 'alerts' },
                { label: 'Low',    data: data.low    || [], backgroundColor: PDR_COLORS.green,  stack: 'alerts' }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'top', labels: { color: PDR_CHART_DEFAULTS.textColor, font: { family: PDR_CHART_DEFAULTS.font, size: 11 } } } },
            scales: {
                x: { stacked: true, grid: { color: PDR_CHART_DEFAULTS.gridColor }, ticks: { font: { family: PDR_CHART_DEFAULTS.font, size: 10 } } },
                y: { stacked: true, grid: { color: PDR_CHART_DEFAULTS.gridColor }, ticks: { font: { family: PDR_CHART_DEFAULTS.font, size: 10 } }, beginAtZero: true }
            }
        }
    });
}

/**
 * Bar chart for packet size distribution
 */
function createSizeDistributionChart(canvasId, sizes) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const arr    = sizes || [];
    const bins   = [0,64,128,256,512,1024,1500];
    const labels = ['<64','64–128','128–256','256–512','512–1024','1024–1500','1500+'];
    const counts = Array(labels.length).fill(0);

    arr.forEach(function (s) {
        for (let i = bins.length - 1; i >= 0; i--) {
            if (s >= bins[i]) { counts[i]++; break; }
        }
    });

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Packets',
                data: counts,
                backgroundColor: 'rgba(0,212,255,.5)',
                borderColor: PDR_COLORS.cyan,
                borderWidth: 1,
                borderRadius: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: PDR_CHART_DEFAULTS.gridColor }, ticks: { font: { family: PDR_CHART_DEFAULTS.font, size: 10 } } },
                y: { grid: { color: PDR_CHART_DEFAULTS.gridColor }, ticks: { font: { family: PDR_CHART_DEFAULTS.font, size: 10 } }, beginAtZero: true }
            }
        }
    });
}

/* Export */
window.PDR_COLORS = PDR_COLORS;
window.charts = window.charts || {};
window.charts.createTimelineChart       = createTimelineChart;
window.charts.createProtocolChart       = createProtocolChart;
window.charts.createAlertsChart         = createAlertsChart;
window.charts.createSizeDistributionChart = createSizeDistributionChart;