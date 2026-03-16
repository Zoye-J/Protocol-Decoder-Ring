/**
 * PDR Dashboard Main JavaScript
 */

// Global variables
let socket = null;
let currentTheme = localStorage.getItem('theme') || 'light';
let charts = {};

// Initialize on document ready
$(document).ready(function() {
    initializeTheme();
    initializeSocket();
    initializeEventListeners();
    startPeriodicUpdates();
});

/**
 * Theme Management
 */
function initializeTheme() {
    if (currentTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
        $('#themeToggle i').removeClass('fa-moon').addClass('fa-sun');
    }
}

$('#themeToggle').click(function() {
    if (currentTheme === 'light') {
        document.documentElement.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
        currentTheme = 'dark';
        $(this).find('i').removeClass('fa-moon').addClass('fa-sun');
    } else {
        document.documentElement.removeAttribute('data-theme');
        localStorage.setItem('theme', 'light');
        currentTheme = 'light';
        $(this).find('i').removeClass('fa-sun').addClass('fa-moon');
    }
});

/**
 * Socket.IO Connection
 */
function initializeSocket() {
    socket = io();
    
    socket.on('connect', function() {
        console.log('Connected to server');
        updateSystemStatus('connected');
    });
    
    socket.on('disconnect', function() {
        console.log('Disconnected from server');
        updateSystemStatus('disconnected');
    });
    
    socket.on('analysis_complete', function(data) {
        if (data.status === 'success') {
            showNotification('success', `Analysis ${data.analysis_id} completed`);
            refreshAnalysesTable();
        } else {
            showNotification('error', `Analysis failed: ${data.error}`);
        }
    });
    
    socket.on('capture_update', function(data) {
        updateCaptureProgress(data);
    });
    
    socket.on('capture_complete', function(data) {
        showNotification('success', `Capture complete: ${data.packet_count} packets saved`);
        $('#captureModal').modal('hide');
    });
}

function updateSystemStatus(status) {
    const statusEl = $('#system-status');
    if (status === 'connected') {
        statusEl.html('<i class="fas fa-circle text-success"></i> Online');
    } else {
        statusEl.html('<i class="fas fa-circle text-danger"></i> Offline');
    }
}

/**
 * Event Listeners
 */
function initializeEventListeners() {
    // Upload button
    $('#uploadBtn').click(uploadFile);
    
    // Start capture button
    $('#startCaptureBtn').click(startCapture);
    
    // Refresh buttons
    $('#refreshAnalyses').click(refreshAnalysesTable);
    $('#refreshAlerts').click(loadAlerts);
    
    // Search inputs
    $('#searchAnalyses').on('keyup', function() {
        analysesTable.search($(this).val()).draw();
    });
}

/**
 * File Upload and Analysis
 */
function uploadFile() {
    const fileInput = $('#fileInput')[0];
    if (!fileInput.files.length) {
        showNotification('warning', 'Please select a file');
        return;
    }
    
    const file = fileInput.files[0];
    const timeout = $('#timeoutInput').val();
    
    const formData = new FormData();
    formData.append('file', file);
    
    // Show progress
    $('#uploadProgress').removeClass('d-none');
    $('#uploadBtn').prop('disabled', true);
    
    $.ajax({
        url: '/api/v1/analyze/file',
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        success: function(response) {
            showNotification('success', `Analysis started: ${response.analysis_id}`);
            $('#uploadModal').modal('hide');
            $('#uploadProgress').addClass('d-none');
            $('#uploadBtn').prop('disabled', false);
            $('#fileInput').val('');
        },
        error: function(xhr) {
            showNotification('error', 'Upload failed: ' + xhr.responseJSON?.error);
            $('#uploadProgress').addClass('d-none');
            $('#uploadBtn').prop('disabled', false);
        }
    });
}

/**
 * Live Capture
 */
function startCapture() {
    const interface = $('#interfaceSelect').val();
    const duration = $('#durationInput').val();
    const filter = $('#filterInput').val();
    
    $('#captureProgress').removeClass('d-none');
    $('#startCaptureBtn').prop('disabled', true);
    
    socket.emit('start_capture', {
        interface: interface,
        duration: duration,
        filter: filter
    });
}

function updateCaptureProgress(data) {
    const percent = (data.duration / data.duration) * 100;
    $('#capturePackets').text(data.packet_count);
    $('#captureProgressBar').css('width', percent + '%').text(Math.round(percent) + '%');
}

/**
 * Load Interfaces
 */
function loadInterfaces() {
    $.get('/api/v1/interfaces', function(interfaces) {
        const select = $('#interfaceSelect');
        select.empty();
        select.append('<option value="">Default Interface</option>');
        
        interfaces.forEach(function(iface) {
            select.append(`<option value="${iface.name}">${iface.name} (${iface.ips.join(', ')})</option>`);
        });
    }).fail(function() {
        console.log('Could not load interfaces');
    });
}

/**
 * Load Dashboard Data
 */
function loadDashboardData() {
    loadStatistics();
    loadAlerts();
    loadTrafficData();
    loadProtocolData();
}

function loadStatistics() {
    $.get('/api/v1/status', function(status) {
        $('#stat-packets').text(status.stats?.total_packets || 0);
        $('#stat-alerts').text(status.stats?.total_alerts || 0);
        $('#stat-signatures').text(status.stats?.total_signatures || 0);
        $('#stat-storage').text(status.storage?.total || '0 MB');
    });
}

function loadAlerts() {
    $.get('/api/v1/alerts?limit=10', function(alerts) {
        const alertsList = $('#alertsList');
        alertsList.empty();
        
        if (alerts.length === 0) {
            alertsList.append('<div class="text-muted text-center py-3">No alerts</div>');
            return;
        }
        
        alerts.forEach(function(alert) {
            const severityClass = alert.severity || 'low';
            const time = new Date(alert.timestamp * 1000).toLocaleString();
            
            alertsList.append(`
                <div class="alert-item ${severityClass}">
                    <div class="d-flex justify-content-between">
                        <span class="alert-type">${alert.type}</span>
                        <span class="alert-time">${time}</span>
                    </div>
                    <div class="alert-description">${alert.description || ''}</div>
                    <small class="text-muted">Analysis: ${alert.analysis_id || 'unknown'}</small>
                </div>
            `);
        });
    });
}

function loadTrafficData() {
    $.get('/api/v1/traffic/timeline', function(data) {
        updateTrafficChart(data);
    });
}

function loadProtocolData() {
    $.get('/api/v1/protocols/distribution', function(data) {
        updateProtocolChart(data);
    });
}

/**
 * Charts
 */
function initializeCharts() {
    // Traffic Chart
    const trafficCtx = document.getElementById('trafficChart')?.getContext('2d');
    if (trafficCtx) {
        charts.traffic = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets',
                    data: [],
                    borderColor: '#0d6efd',
                    backgroundColor: 'rgba(13, 110, 253, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }
    
    // Protocol Chart
    const protoCtx = document.getElementById('protocolChart')?.getContext('2d');
    if (protoCtx) {
        charts.protocol = new Chart(protoCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#0d6efd', '#198754', '#dc3545', '#ffc107', 
                        '#0dcaf0', '#6c757d', '#6610f2', '#d63384'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    }
}

function updateTrafficChart(data) {
    if (charts.traffic) {
        charts.traffic.data.labels = data.labels || [];
        charts.traffic.data.datasets[0].data = data.values || [];
        charts.traffic.update();
    }
}

function updateProtocolChart(data) {
    if (charts.protocol) {
        charts.protocol.data.labels = data.labels || [];
        charts.protocol.data.datasets[0].data = data.values || [];
        charts.protocol.update();
    }
}

/**
 * Analyses Table
 */
let analysesTable = null;

function refreshAnalysesTable() {
    if ($.fn.DataTable.isDataTable('#analysesTable')) {
        analysesTable = $('#analysesTable').DataTable();
        analysesTable.ajax.reload();
    } else {
        analysesTable = $('#analysesTable').DataTable({
            ajax: {
                url: '/api/v1/analyses',
                dataSrc: ''
            },
            columns: [
                { data: 'id' },
                { data: 'timestamp' },
                { data: 'packets' },
                { 
                    data: 'alerts',
                    render: function(data) {
                        return `<span class="badge bg-danger">${data}</span>`;
                    }
                },
                {
                    data: 'id',
                    render: function(data) {
                        return `<a href="/analysis/${data}" class="btn btn-sm btn-primary">
                                   <i class="fas fa-eye"></i> View
                                </a>`;
                    }
                }
            ],
            pageLength: 10,
            order: [[1, 'desc']]
        });
    }
}

/**
 * Notifications
 */
function showNotification(type, message) {
    // Create toast container if it doesn't exist
    if (!$('#toastContainer').length) {
        $('body').append('<div id="toastContainer" class="position-fixed bottom-0 end-0 p-3" style="z-index: 9999"></div>');
    }
    
    const toastId = 'toast-' + Date.now();
    const bgClass = type === 'success' ? 'bg-success' : (type === 'error' ? 'bg-danger' : 'bg-warning');
    
    const toast = `
        <div id="${toastId}" class="toast align-items-center text-white ${bgClass} border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    
    $('#toastContainer').append(toast);
    const toastEl = new bootstrap.Toast(document.getElementById(toastId), { delay: 5000 });
    toastEl.show();
    
    // Remove after hidden
    $(`#${toastId}`).on('hidden.bs.toast', function() {
        $(this).remove();
    });
}

/**
 * Periodic Updates
 */
function startPeriodicUpdates() {
    // Update stats every 30 seconds
    setInterval(loadDashboardData, 30000);
    
    // Update timestamp every second
    setInterval(function() {
        $('#live-timestamp').text(new Date().toLocaleString());
    }, 1000);
}

/**
 * Utility Functions
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatTimestamp(timestamp) {
    return new Date(timestamp * 1000).toLocaleString();
}

function getSeverityBadge(severity) {
    const colors = {
        'high': 'danger',
        'medium': 'warning',
        'low': 'success'
    };
    return `<span class="badge bg-${colors[severity] || 'secondary'}">${severity}</span>`;
}