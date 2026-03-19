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
    console.log('[PDR] uploadBtn found:', btn);
    if (!btn) return;

    // Remove any existing listeners to prevent duplicates
    btn.replaceWith(btn.cloneNode(true));
    const newBtn = document.getElementById('uploadBtn');
    
    newBtn.addEventListener('click', function (e) {
        e.preventDefault(); // Prevent any default behavior
        console.log('[PDR] Upload button clicked'); // Debug log
        
        const fileInput = document.getElementById('fileInput');
        if (!fileInput) {
            console.error('[PDR] File input not found');
            showNotification('error', 'File input not found');
            return;
        }
        
        console.log('[PDR] Files selected:', fileInput.files.length);
        
        if (!fileInput.files.length) {
            showNotification('warning', 'Please select a file first');
            return;
        }

        const file = fileInput.files[0];
        console.log('[PDR] File to upload:', file.name, file.size, 'bytes');

        const formData = new FormData();
        formData.append('file', file);

        const progress = document.getElementById('uploadProgress');
        if (progress) progress.style.display = 'block';
        
        newBtn.disabled = true;
        console.log('[PDR] Making fetch request to /api/v1/analyze/file...');
        
        fetch('/api/v1/analyze/file', {
            method: 'POST',
            headers: { 
                'X-API-Key': 'change-this-in-production' // Hardcode for testing
            },
            body: formData
        })
        .then(response => {
            console.log('[PDR] Response status:', response.status);
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.error || 'Upload failed') });
            }
            return response.json();
        })
        .then(data => {
            console.log('[PDR] Upload success:', data);
            if (data.error) throw new Error(data.error);
            
            showNotification('success', 'Analysis started: ' + data.analysis_id);
            
            // Hide modal
            const modalEl = document.getElementById('uploadModal');
            const modal = bootstrap.Modal.getInstance(modalEl);
            if (modal) modal.hide();
            
            // Clear input
            fileInput.value = '';
            
            // Show a "waiting" notification
            showNotification('info', 'Analysis running — results will appear in ~35 seconds');
            
            // Poll for completion
            let attempts = 0;
            const pollInterval = setInterval(function() {
                attempts++;
                console.log('[PDR] Polling analysis:', data.analysis_id, 'attempt', attempts);
                
                fetch('/api/v1/analysis/' + data.analysis_id)
                    .then(r => r.json())
                    .then(result => {
                        if (!result.error) {
                            console.log('[PDR] Analysis complete!');
                            clearInterval(pollInterval);
                            showNotification('success', 
                                'Analysis complete — ' + 
                                (result.alerts?.length || 0) + ' alerts found');
                            
                            // Reload page data
                            if (typeof loadStats === 'function') loadStats();
                            if (typeof loadRecentAlerts === 'function') loadRecentAlerts();
                            if (typeof window.loadDashboardData === 'function') window.loadDashboardData();
                            
                            // Refresh analyses table
                            const tbody = document.getElementById('analyses-tbody');
                            if (tbody) {
                                fetch('/api/v1/analyses')
                                    .then(r => r.json())
                                    .then(analyses => {
                                        tbody.innerHTML = '';
                                        analyses.slice(0, 10).forEach(a => {
                                            const row = document.createElement('tr');
                                            row.innerHTML = `
                                                <td style="font-family:var(--font-mono);font-size:11px;color:var(--accent);">${a.id}</td>
                                                <td style="font-family:var(--font-mono);font-size:11px;">${(a.timestamp||'').substring(0,19)}</td>
                                                <td>${a.packets||0}</td>
                                                <td>${a.alerts > 0 ? '<span class="badge-pdr badge-high">'+a.alerts+'</span>' : '0'}</td>
                                                <td><a href="/analysis/${a.id}" class="btn-pdr btn-pdr-ghost" style="font-size:11px;padding:4px 10px;">View →</a></td>
                                            `;
                                            tbody.appendChild(row);
                                        });
                                    });
                            }
                        }
                    })
                    .catch(err => console.log('[PDR] Poll error:', err));
                
                // Stop polling after 2 minutes
                if (attempts > 24) {
                    clearInterval(pollInterval);
                    showNotification('warning', 'Analysis is taking longer than expected — check Reports page');
                }
            }, 5000);
        })
        .catch(err => {
            console.error('[PDR] Upload error:', err);
            showNotification('error', 'Upload failed: ' + err.message);
        })
        .finally(() => {
            if (progress) progress.style.display = 'none';
            newBtn.disabled = false;
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