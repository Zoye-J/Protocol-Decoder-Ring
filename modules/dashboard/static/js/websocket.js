/**
 * PDR Dashboard — websocket.js
 * Real-time event handlers. Attaches to window.pdrSocket which is
 * created by dashboard.js. Safe to load before socket is ready.
 */

(function attachWebSocketHandlers() {
    /* Wait until the socket is available (dashboard.js runs first) */
    function waitForSocket(cb, attempts) {
        attempts = attempts || 0;
        if (window.pdrSocket) {
            cb(window.pdrSocket);
        } else if (attempts < 20) {
            setTimeout(function () { waitForSocket(cb, attempts + 1); }, 150);
        } else {
            console.warn('[PDR] websocket.js: socket not available after waiting');
        }
    }

    waitForSocket(function (socket) {

        /* ── Packet captured ── */
        socket.on('packet_captured', function (packet) {
            updatePacketCounter();
            addRecentPacket(packet);
            updateTrafficChartRealTime(packet);
        });

        /* ── Alert generated ── */
        socket.on('alert_generated', function (alert) {
            if (typeof showNotification === 'function') {
                showNotification('warning', 'New alert: ' + alert.type);
            }
            addAlertToList(alert);
            bumpAlertCounter();
        });

        /* ── Analysis progress ── */
        socket.on('analysis_progress', function (data) {
            const bar    = document.getElementById('analysis-progress-bar');
            const status = document.getElementById('analysis-status');
            if (bar)    bar.style.width = (data.percent || 0) + '%';
            if (status) status.textContent = data.message || 'Processing…';
        });

        /* ── Signature generated ── */
        socket.on('signature_generated', function (data) {
            if (typeof showNotification === 'function') {
                showNotification('success', 'Signature generated: ' + (data.name || ''));
            }
        });

    });

})();

/* ── Helper functions ── */

function updatePacketCounter() {
    const el = document.getElementById('live-packet-count');
    if (!el) return;
    el.textContent = (parseInt(el.textContent) || 0) + 1;
}

function addRecentPacket(packet) {
    const tbody = document.querySelector('#recent-packets tbody');
    if (!tbody) return;

    const ts    = packet.time ? new Date(packet.time * 1000).toLocaleTimeString() : '—';
    const proto = packet.protocol || 'Unknown';
    const src   = packet.src ? packet.src + (packet.sport ? ':' + packet.sport : '') : '—';
    const dst   = packet.dst ? packet.dst + (packet.dport ? ':' + packet.dport : '') : '—';

    const row = document.createElement('tr');
    row.innerHTML =
        '<td style="font-family:var(--font-mono);font-size:11px;">' + ts    + '</td>' +
        '<td style="font-family:var(--font-mono);font-size:11px;color:var(--accent);">' + proto + '</td>' +
        '<td style="font-family:var(--font-mono);font-size:11px;">' + src   + '</td>' +
        '<td style="font-family:var(--font-mono);font-size:11px;">' + dst   + '</td>' +
        '<td style="font-family:var(--font-mono);font-size:11px;">' + (packet.length || 0) + ' B</td>';

    tbody.insertBefore(row, tbody.firstChild);

    /* Keep at most 50 rows */
    while (tbody.children.length > 50) {
        tbody.removeChild(tbody.lastChild);
    }
}

function addAlertToList(alert) {
    const container = document.getElementById('live-alerts') ||
                      document.getElementById('recent-alerts-list');
    if (!container) return;

    const sev  = alert.severity || 'medium';
    const time = new Date().toLocaleTimeString();

    const el = document.createElement('div');
    el.className = 'alert-item ' + sev;
    el.style.marginBottom = '8px';
    el.innerHTML =
        '<div style="display:flex;justify-content:space-between;margin-bottom:4px;">' +
            '<span class="alert-type">' + (alert.type || '') + '</span>' +
            '<span class="alert-time">' + time + '</span>' +
        '</div>' +
        '<div class="alert-description">' + (alert.description || '') + '</div>';

    container.insertBefore(el, container.firstChild);

    while (container.children.length > 20) {
        container.removeChild(container.lastChild);
    }
}

function bumpAlertCounter() {
    const el = document.getElementById('alert-counter');
    if (!el) return;
    el.textContent = (parseInt(el.textContent) || 0) + 1;
}

function updateTrafficChartRealTime(packet) {
    const chart = window.charts?.traffic;
    if (!chart) return;

    const now = new Date().toLocaleTimeString();
    chart.data.labels.push(now);
    chart.data.datasets[0].data.push(packet.length || 1);

    if (chart.data.labels.length > 30) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
    }

    chart.update('none'); /* 'none' skips animation for real-time feel */
}