/**
 * Chart Visualizations
 */

// Chart color schemes
const colorSchemes = {
    primary: ['#0d6efd', '#198754', '#dc3545', '#ffc107', '#0dcaf0', '#6c757d'],
    pastel: ['#a8d5e5', '#b5e5d5', '#f9d5b5', '#f5b5b5', '#d5b5e5', '#b5b5f5'],
    gradient: ['#4158D0', '#C850C0', '#FFCC70', '#2193b0', '#6dd5ed', '#cc2b5e']
};

/**
 * Create Timeline Chart
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
                data: data.packets || [],
                borderColor: '#0d6efd',
                backgroundColor: 'rgba(13, 110, 253, 0.1)',
                borderWidth: 2,
                pointRadius: 3,
                pointHoverRadius: 5,
                tension: 0.4,
                fill: true
            }, {
                label: 'Bytes (KB)',
                data: data.bytes || [],
                borderColor: '#198754',
                backgroundColor: 'rgba(25, 135, 84, 0.1)',
                borderWidth: 2,
                pointRadius: 3,
                pointHoverRadius: 5,
                tension: 0.4,
                fill: true,
                yAxisID: 'y1'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false
            },
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.dataset.label.includes('Bytes')) {
                                label += formatBytes(context.raw);
                            } else {
                                label += context.raw;
                            }
                            return label;
                        }
                    }
                }
            },
            scales: {
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Packets'
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'Bytes'
                    },
                    grid: {
                        drawOnChartArea: false
                    }
                }
            }
        }
    });
}

/**
 * Create Protocol Distribution Chart
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
                backgroundColor: colorSchemes.primary,
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        boxWidth: 12,
                        padding: 15
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create Alerts Timeline Chart
 */
function createAlertsChart(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.labels || [],
            datasets: [{
                label: 'High',
                data: data.high || [],
                backgroundColor: '#dc3545',
                stack: 'alerts'
            }, {
                label: 'Medium',
                data: data.medium || [],
                backgroundColor: '#ffc107',
                stack: 'alerts'
            }, {
                label: 'Low',
                data: data.low || [],
                backgroundColor: '#198754',
                stack: 'alerts'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                }
            },
            scales: {
                x: {
                    stacked: true,
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    stacked: true,
                    title: {
                        display: true,
                        text: 'Number of Alerts'
                    },
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Create Flow Sankey Diagram (simplified)
 */
function createFlowChart(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    // Simplified flow visualization using bar chart
    const sources = [...new Set(data.flows.map(f => f.src))].slice(0, 10);
    const destinations = [...new Set(data.flows.map(f => f.dst))].slice(0, 10);
    
    return new Chart(ctx, {
        type: 'matrix',
        data: {
            labels: sources,
            datasets: destinations.map(dst => ({
                label: dst,
                data: sources.map(src => {
                    const flow = data.flows.find(f => f.src === src && f.dst === dst);
                    return flow ? flow.bytes : 0;
                })
            }))
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const src = context.label;
                            const dst = context.dataset.label;
                            const bytes = context.raw;
                            return `${src} → ${dst}: ${formatBytes(bytes)}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Source IP'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Destination IP'
                    }
                }
            }
        }
    });
}

/**
 * Create Heat Map for Timing Analysis
 */
function createTimingHeatmap(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    // Prepare data for heatmap
    const intervals = data.intervals || [];
    const matrix = [];
    const size = Math.min(20, Math.floor(Math.sqrt(intervals.length)));
    
    for (let i = 0; i < size; i++) {
        matrix[i] = [];
        for (let j = 0; j < size; j++) {
            const idx = i * size + j;
            matrix[i][j] = idx < intervals.length ? intervals[idx] : 0;
        }
    }
    
    return new Chart(ctx, {
        type: 'matrix',
        data: {
            datasets: [{
                label: 'Inter-arrival Times',
                data: matrix.map((row, i) => 
                    row.map((value, j) => ({
                        x: j,
                        y: i,
                        v: value
                    }))
                ).flat(),
                backgroundColor: function(context) {
                    const value = context.dataset.data[context.dataIndex].v;
                    const alpha = Math.min(1, value / 5); // Normalize
                    return `rgba(220, 53, 69, ${alpha})`;
                },
                borderWidth: 1,
                borderColor: '#ffffff',
                width: 20,
                height: 20
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: false,
                tooltip: {
                    callbacks: {
                        title: function() {
                            return '';
                        },
                        label: function(context) {
                            const value = context.raw.v;
                            return `Interval: ${value.toFixed(3)}s`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    type: 'linear',
                    offset: true,
                    grid: { display: false },
                    ticks: { display: false }
                },
                y: {
                    type: 'linear',
                    offset: true,
                    grid: { display: false },
                    ticks: { display: false }
                }
            }
        }
    });
}

/**
 * Create Size Distribution Chart
 */
function createSizeDistributionChart(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    // Create histogram bins
    const sizes = data.sizes || [];
    const binCount = 20;
    const max = Math.max(...sizes, 1500);
    const binSize = max / binCount;
    
    const bins = Array(binCount).fill(0);
    sizes.forEach(size => {
        const binIndex = Math.min(binCount - 1, Math.floor(size / binSize));
        bins[binIndex]++;
    });
    
    const labels = bins.map((_, i) => `${Math.round(i * binSize)}-${Math.round((i + 1) * binSize)}`);
    
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Packet Count',
                data: bins,
                backgroundColor: '#0d6efd',
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Packets: ${context.raw}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Packet Size (bytes)'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Frequency'
                    },
                    beginAtZero: true
                }
            }
        }
    });
}

// Export chart creation functions
window.charts = {
    createTimelineChart,
    createProtocolChart,
    createAlertsChart,
    createFlowChart,
    createTimingHeatmap,
    createSizeDistributionChart
};