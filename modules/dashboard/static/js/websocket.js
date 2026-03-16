/**
 * WebSocket Real-time Updates
 */

// WebSocket event handlers
socket.on('packet_captured', function(data) {
    // Update packet counter
    updatePacketCounter(data);
    
    // Add to recent packets table
    addRecentPacket(data);
    
    // Update traffic chart
    updateTrafficChartRealTime(data);
});

socket.on('alert_generated', function(data) {
    // Show notification
    showNotification('warning', `New alert: ${data.type}`);
    
    // Add to alerts list
    addAlertToList(data);
    
    // Update alert counter
    updateAlertCounter();
});

socket.on('analysis_progress', function(data) {
    // Update progress bar
    updateAnalysisProgress(data);
});

socket.on('signature_generated', function(data) {
    showNotification('success', `New signature generated: ${data.name}`);
    refreshSignaturesList();
});

// Update functions
function updatePacketCounter(data) {
    const counter = $('#live-packet-count');
    if (counter.length) {
        let count = parseInt(counter.text()) || 0;
        count++;
        counter.text(count);
    }
}

function addRecentPacket(packet) {
    const table = $('#recent-packets tbody');
    if (!table.length) return;
    
    // Add new row
    const row = `
        <tr>
            <td>${formatTimestamp(packet.time)}</td>
            <td>${packet.protocol || 'Unknown'}</td>
            <td>${packet.src}:${packet.sport}</td>
            <td>${packet.dst}:${packet.dport}</td>
            <td>${packet.length} bytes</td>
        </tr>
    `;
    
    table.prepend(row);
    
    // Keep only last 50 rows
    if (table.children().length > 50) {
        table.children().last().remove();
    }
}

function addAlertToList(alert) {
    const container = $('#live-alerts');
    if (!container.length) return;
    
    const severityClass = alert.severity || 'medium';
    const time = new Date().toLocaleTimeString();
    
    const alertEl = `
        <div class="alert-item ${severityClass} fade-in">
            <div class="d-flex justify-content-between">
                <span class="alert-type">${alert.type}</span>
                <span class="alert-time">${time}</span>
            </div>
            <div class="alert-description">${alert.description || ''}</div>
        </div>
    `;
    
    container.prepend(alertEl);
    
    // Keep only last 20 alerts
    if (container.children().length > 20) {
        container.children().last().remove();
    }
}

function updateAnalysisProgress(data) {
    const progressBar = $('#analysis-progress .progress-bar');
    const statusText = $('#analysis-status');
    
    if (progressBar.length) {
        progressBar.css('width', data.percent + '%');
        progressBar.text(data.percent + '%');
    }
    
    if (statusText.length) {
        statusText.text(data.message || 'Processing...');
    }
}

function refreshSignaturesList() {
    if ($('#signatures-list').length) {
        $.get('/api/v1/signatures?limit=5', function(signatures) {
            const list = $('#signatures-list');
            list.empty();
            
            signatures.forEach(function(sig) {
                list.append(`
                    <div class="list-group-item">
                        <div class="d-flex justify-content-between">
                            <span>${sig.name}</span>
                            <span class="badge bg-info">${sig.format}</span>
                        </div>
                        <small class="text-muted">${formatTimestamp(sig.modified)}</small>
                    </div>
                `);
            });
        });
    }
}

function updateAlertCounter() {
    const counter = $('#alert-counter');
    if (counter.length) {
        let count = parseInt(counter.text()) || 0;
        count++;
        counter.text(count);
        
        // Add animation
        counter.addClass('pulse');
        setTimeout(() => counter.removeClass('pulse'), 500);
    }
}

function updateTrafficChartRealTime(packet) {
    if (charts.traffic) {
        // Add new data point
        const now = new Date().toLocaleTimeString();
        charts.traffic.data.labels.push(now);
        charts.traffic.data.datasets[0].data.push(packet.length || 1);
        
        // Keep only last 20 points
        if (charts.traffic.data.labels.length > 20) {
            charts.traffic.data.labels.shift();
            charts.traffic.data.datasets[0].data.shift();
        }
        
        charts.traffic.update();
    }
}

// Export functions for use in other scripts
window.websocketHandlers = {
    updatePacketCounter,
    addRecentPacket,
    addAlertToList,
    updateAnalysisProgress,
    refreshSignaturesList,
    updateAlertCounter
};