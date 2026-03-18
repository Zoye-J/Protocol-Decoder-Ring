/**
 * PDR Dashboard — dashboard.js
 * Page-level logic. showNotification() and formatBytes() live in base.html.
 * This file must not redefine them.
 */

/* ── Globals ── */
window.pdrSocket = null;   // socket instance shared across scripts
window.charts    = {};     // chart instances

/* ── Init ── */
$(document).ready(function () {
    initSocket();
    bindUploadModal();
    bindCaptureModal();
    startClock();
});

/* ── Socket ── */
function initSocket() {
    try {
        window.pdrSocket = io();

        window.pdrSocket.on('connect', function () {
            console.log('[PDR] Socket connected');
        });

        window.pdrSocket.on('disconnect', function () {
            console.log('[PDR] Socket disconnected');
        });

        window.pdrSocket.on('analysis_complete', function (data) {
            if (data.status === 'success') {
                showNotification('success', 'Analysis ' + data.analysis_id + ' complete — ' + (data.packet_count || 0) + ' packets');
            } else {
                showNotification('error', 'Analysis failed: ' + (data.error || 'unknown error'));
            }
        });

        window.pdrSocket.on('capture_update', function (data) {
            // Update progress bar if visible
            const bar = document.getElementById('cap-bar');
            const status = document.getElementById('cap-status');
            if (bar) bar.style.width = Math.min((data.duration / (window._capDuration || 30)) * 100, 100) + '%';
            if (status) status.textContent = data.packet_count + ' packets · ' + data.duration.toFixed(1) + 's';
        });

        window.pdrSocket.on('capture_complete', function (data) {
            showNotification('success', 'Capture complete: ' + data.packet_count + ' packets saved');
            const modal = bootstrap.Modal.getInstance(document.getElementById('captureModal'));
            if (modal) modal.hide();
        });

    } catch (e) {
        console.warn('[PDR] Socket.IO not available:', e.message);
    }
}

/* ── Upload modal ── */
function bindUploadModal() {
    const btn = document.getElementById('uploadBtn');
    if (!btn) return;

    btn.addEventListener('click', function () {
        const fileInput = document.getElementById('fileInput');
        if (!fileInput || !fileInput.files.length) {
            showNotification('warning', 'Please select a file first');
            return;
        }

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        const progress = document.getElementById('uploadProgress');
        if (progress) progress.style.display = 'block';
        btn.disabled = true;

        fetch('/api/v1/analyze/file', {
            method: 'POST',
            headers: { 'X-API-Key': window.PDR_API_KEY || 'change-this-in-production' },
            body: formData
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) throw new Error(data.error);
            showNotification('success', 'Analysis started: ' + data.analysis_id);
            const modal = bootstrap.Modal.getInstance(document.getElementById('uploadModal'));
            if (modal) modal.hide();
            fileInput.value = '';
        })
        .catch(err => {
            showNotification('error', 'Upload failed: ' + err.message);
        })
        .finally(() => {
            if (progress) progress.style.display = 'none';
            btn.disabled = false;
        });
    });
}

/* ── Capture modal ── */
function bindCaptureModal() {
    const btn = document.getElementById('startCaptureBtn') || document.getElementById('start-cap-btn');
    if (!btn) return;

    btn.addEventListener('click', function () {
        const iface    = (document.getElementById('interfaceSelect') || document.getElementById('cap-iface'))?.value || '';
        const duration = parseInt((document.getElementById('durationInput') || document.getElementById('cap-dur'))?.value) || 30;
        const filter   = (document.getElementById('filterInput') || document.getElementById('cap-filter'))?.value || '';
        const maxPkts  = parseInt(document.getElementById('cap-max')?.value) || 1000;

        window._capDuration = duration;

        const progress = document.getElementById('cap-progress') || document.getElementById('captureProgress');
        if (progress) progress.style.display = 'block';

        if (window.pdrSocket) {
            window.pdrSocket.emit('start_capture', {
                interface: iface,
                duration: duration,
                filter: filter,
                limit: maxPkts
            });
            showNotification('info', 'Capture started (' + duration + 's)');
        } else {
            showNotification('error', 'Socket not connected — cannot start live capture');
        }
    });
}

/* ── Clock (sidebar + topbar already handled in base.html) ── */
function startClock() {
    const el = document.getElementById('live-timestamp');
    if (!el) return;
    setInterval(function () {
        el.textContent = new Date().toLocaleString();
    }, 1000);
}

/* ── Load interfaces into any <select id="interfaceSelect"> ── */
function loadInterfaces() {
    const selectors = ['#interfaceSelect', '#cap-iface'];
    selectors.forEach(function (sel) {
        const el = document.querySelector(sel);
        if (!el) return;
        fetch('/api/v1/interfaces')
            .then(r => r.json())
            .then(list => {
                el.innerHTML = '<option value="">Default Interface (auto)</option>';
                (list || []).forEach(function (iface) {
                    const opt = document.createElement('option');
                    opt.value = iface.name;
                    opt.textContent = iface.name + (iface.ips?.length ? ' — ' + iface.ips[0] : '');
                    el.appendChild(opt);
                });
            })
            .catch(() => {/* silently ignore */});
    });
}

/* ── Exported helpers (used by inline page scripts) ── */
window.loadInterfaces = loadInterfaces;