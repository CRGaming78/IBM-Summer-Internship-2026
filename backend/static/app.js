// ============================
// Wireless Network Security Monitor
// Dashboard JavaScript
// ============================

// --- State ---
var ws = null;
var reconnectTimer = null;
var frameChart = null;
var channelChart = null;
var alertList = [];
var devices = {};   // keyed by MAC
var accessPoints = {}; // keyed by BSSID
var channelCounts = {}; // keyed by channel number

// how many data points to keep on the frame chart (~5 min at 1/sec)
var MAX_CHART_POINTS = 300;
var MAX_ALERTS = 50;

// per-second counters for frame types (reset each second)
var frameCounters = { DEAUTH: 0, BEACON: 0, PROBE_REQ: 0, DISASSOC: 0 };
var chartTickInterval = null;

// Dirty flags: mark tables dirty, render on a timer instead of every event
var deviceTableDirty = false;
var apTableDirty = false;

// Per-device threat scores: keyed by MAC
var deviceScores = {};

// Per-device risk reasons: keyed by MAC
var deviceReasons = {};

// Column sort state
var deviceSort = { col: 'last_seen', dir: 'desc' };
var apSort = { col: 'ssid', dir: 'asc' };

// ============================================================
// MAC Vendor OUI Database (top manufacturers)
// ============================================================

var OUI_DB = {
    '00:03:7F': 'Atheros', '00:0C:29': 'VMware', '00:0D:93': 'Apple',
    '00:11:22': 'Cimsys', '00:14:22': 'Dell', '00:17:88': 'Philips Hue',
    '00:1A:11': 'Google', '00:1B:63': 'Apple', '00:1C:B3': 'Apple',
    '00:1E:C2': 'Apple', '00:21:6A': 'Intel', '00:23:12': 'Apple',
    '00:23:6C': 'Apple', '00:23:DF': 'Apple', '00:24:36': 'Apple',
    '00:25:00': 'Apple', '00:25:BC': 'Apple', '00:26:08': 'Apple',
    '00:26:4A': 'Apple', '00:26:B0': 'Apple', '00:26:BB': 'Apple',
    '00:30:65': 'Apple', '00:3E:E1': 'Apple', '00:50:56': 'VMware',
    '00:E0:4C': 'Realtek', '00:E0:63': 'Cabletron',
    '04:E5:36': 'Intel', '08:00:27': 'VirtualBox',
    '08:66:98': 'Apple', '08:6D:41': 'Apple',
    '0C:4D:E9': 'Apple', '0C:74:C2': 'Apple',
    '10:DD:B1': 'Apple', '10:41:7F': 'Apple',
    '14:10:9F': 'Apple', '14:5A:05': 'Apple',
    '18:AF:8F': 'Apple', '18:E7:F4': 'Apple',
    '1C:36:BB': 'Apple', '1C:91:48': 'Apple',
    '20:78:F0': 'Apple', '20:A2:E4': 'Apple',
    '24:A0:74': 'Apple', '24:AB:81': 'Apple',
    '28:6A:BA': 'Apple', '28:CF:DA': 'Apple',
    '2C:B4:3A': 'Samsung', '2C:33:11': 'Cisco',
    '30:10:E4': 'Samsung', '30:07:4D': 'Samsung',
    '34:23:BA': 'Samsung', '34:14:5F': 'Samsung',
    '38:01:97': 'Apple', '38:C9:86': 'Apple',
    '3C:15:C2': 'Apple', '3C:22:FB': 'Apple',
    '3C:D9:2B': 'HP', '3C:E0:72': 'Apple',
    '40:4D:7F': 'Apple', '40:6C:8F': 'Apple',
    '40:B0:FA': 'Apple', '44:D8:84': 'Apple',
    '48:60:BC': 'Apple', '48:A1:95': 'Apple',
    '4C:32:75': 'Apple', '4C:57:CA': 'Apple',
    '50:32:37': 'Apple', '50:BC:96': 'Apple',
    '54:26:96': 'Apple', '54:72:4F': 'Apple',
    '54:9F:13': 'Apple', '58:1F:AA': 'Apple',
    '58:55:CA': 'Apple', '5C:59:48': 'Apple',
    '5C:89:9A': 'Apple', '5C:F7:E6': 'Apple',
    '60:C5:47': 'Apple', '60:FA:CD': 'Apple',
    '64:20:0C': 'Apple', '64:76:BA': 'Apple',
    '68:5B:35': 'Apple', '68:96:7B': 'Apple',
    '68:A8:6D': 'Apple', '6C:4D:73': 'Apple',
    '6C:94:66': 'Apple', '6C:C2:17': 'Apple',
    '70:11:24': 'Apple', '70:3E:AC': 'Apple',
    '70:56:81': 'Apple', '70:CD:60': 'Apple',
    '70:DE:E2': 'Apple', '74:E1:B6': 'Apple',
    '78:31:C1': 'Apple', '78:67:D7': 'Apple',
    '78:CA:39': 'Apple', '7C:04:D0': 'Apple',
    '7C:6D:62': 'Apple', '7C:D1:C3': 'Apple',
    '80:49:71': 'Apple', '80:E6:50': 'Apple',
    '84:38:35': 'Apple', '84:85:06': 'Apple',
    '84:FC:FE': 'Apple', '88:C6:63': 'Apple',
    '88:E9:FE': 'Apple', '8C:7C:92': 'Apple',
    '8C:85:90': 'Apple', '90:27:E4': 'Apple',
    '90:8D:6C': 'Apple', '90:B2:1F': 'Apple',
    '94:E9:6A': 'Apple', '98:01:A7': 'Apple',
    '98:D6:BB': 'Apple', '98:E0:D9': 'Apple',
    '9C:20:7B': 'Apple', '9C:35:EB': 'Apple',
    'A0:99:9B': 'Apple', 'A4:67:06': 'Apple',
    'A4:B1:97': 'Apple', 'A4:D1:8C': 'Apple',
    'A8:20:66': 'Apple', 'A8:51:5B': 'Apple',
    'A8:66:7F': 'Apple', 'A8:86:DD': 'Apple',
    'A8:BB:CF': 'Apple', 'AC:3C:0B': 'Apple',
    'AC:BC:32': 'Apple', 'AC:FD:CE': 'Apple',
    'B0:19:C6': 'Apple', 'B0:34:95': 'Apple',
    'B0:65:BD': 'Apple', 'B4:18:D1': 'Apple',
    'B4:F0:AB': 'Apple', 'B8:17:C2': 'Apple',
    'B8:27:EB': 'Raspberry Pi', 'B8:C1:11': 'Apple',
    'B8:E8:56': 'Apple', 'B8:F6:B1': 'Apple',
    'BC:3A:EA': 'Apple', 'BC:52:B7': 'Apple',
    'BC:54:36': 'Apple', 'BC:67:78': 'Apple',
    'C0:63:94': 'Apple', 'C0:84:7A': 'Apple',
    'C0:9A:D0': 'Apple', 'C0:CC:F8': 'Apple',
    'C4:2C:03': 'Apple', 'C8:1E:E7': 'Apple',
    'C8:2A:14': 'Apple', 'C8:33:4B': 'Apple',
    'C8:69:CD': 'Apple', 'C8:B5:B7': 'Apple',
    'CC:08:E0': 'Apple', 'CC:29:F5': 'Apple',
    'D0:23:DB': 'Apple', 'D0:25:98': 'Apple',
    'D0:33:11': 'Apple', 'D0:4F:7E': 'Apple',
    'D4:61:9D': 'Apple', 'D4:F4:6F': 'Apple',
    'D8:1D:72': 'Apple', 'D8:30:62': 'Apple',
    'D8:9E:3F': 'Apple', 'DC:2B:2A': 'Apple',
    'DC:37:14': 'Apple', 'DC:56:E7': 'Apple',
    'DC:A4:CA': 'Apple', 'E0:5F:45': 'Apple',
    'E0:66:78': 'Apple', 'E0:B5:2D': 'Apple',
    'E0:C7:67': 'Apple', 'E0:F5:C6': 'Apple',
    'E4:25:E7': 'Apple', 'E4:C6:3D': 'Apple',
    'E8:06:88': 'Apple', 'E8:80:2E': 'Apple',
    'E8:B2:AC': 'Apple', 'F0:18:98': 'Apple',
    'F0:24:75': 'Apple', 'F0:79:60': 'Apple',
    'F0:B4:79': 'Apple', 'F0:CB:A1': 'Apple',
    'F0:D1:A9': 'Apple', 'F0:DB:E2': 'Apple',
    'F4:1B:A1': 'Apple', 'F4:37:B7': 'Apple',
    'F8:1E:DF': 'Apple', 'F8:27:93': 'Apple',
    'F8:E0:79': 'Motorola',
    // Samsung
    '00:07:AB': 'Samsung', '00:12:FB': 'Samsung', '00:13:77': 'Samsung',
    '00:15:99': 'Samsung', '00:16:32': 'Samsung', '00:17:D5': 'Samsung',
    '00:18:AF': 'Samsung', '00:1A:8A': 'Samsung', '00:1B:98': 'Samsung',
    '00:1C:43': 'Samsung', '00:1D:25': 'Samsung', '00:1E:E1': 'Samsung',
    '00:1E:E2': 'Samsung', '00:21:19': 'Samsung', '00:21:D1': 'Samsung',
    '00:23:39': 'Samsung', '00:23:D6': 'Samsung', '00:23:D7': 'Samsung',
    '00:24:54': 'Samsung', '00:24:91': 'Samsung', '00:24:E9': 'Samsung',
    '00:25:66': 'Samsung', '00:25:67': 'Samsung', '00:26:37': 'Samsung',
    '08:08:C2': 'Samsung', '08:37:3D': 'Samsung', '08:D4:2B': 'Samsung',
    '0C:DF:A4': 'Samsung', '10:1D:C0': 'Samsung', '14:49:E0': 'Samsung',
    '14:89:FD': 'Samsung', '18:22:7E': 'Samsung', '1C:62:B8': 'Samsung',
    '24:4B:03': 'Samsung', '28:98:7B': 'Samsung', '2C:AE:2B': 'Samsung',
    '30:CD:A7': 'Samsung', '34:C3:AC': 'Samsung', '38:01:46': 'Samsung',
    // Google, Intel, Xiaomi, Huawei, TP-Link, Netgear, etc.
    '3C:5A:B4': 'Google', '54:60:09': 'Google', 'F4:F5:D8': 'Google',
    '00:1F:3B': 'Intel', '3C:97:0E': 'Intel', '68:17:29': 'Intel',
    '8C:16:45': 'Intel', 'A4:34:D9': 'Intel', 'B4:D5:BD': 'Intel',
    '9C:A5:25': 'Xiaomi', '28:6C:07': 'Xiaomi', '64:CE:84': 'Xiaomi',
    '74:23:44': 'Xiaomi', '78:11:DC': 'Xiaomi', '04:CF:8C': 'Xiaomi',
    '00:E0:FC': 'Huawei', '04:02:1F': 'Huawei', '04:C0:6F': 'Huawei',
    '20:F3:A3': 'Huawei', '24:09:95': 'Huawei', '30:D1:7E': 'Huawei',
    '48:AD:08': 'Huawei', '4C:B1:6C': 'Huawei', '5C:C3:07': 'Huawei',
    '70:72:3C': 'Huawei', '88:28:B3': 'Huawei', 'AC:CF:85': 'Huawei',
    '00:1D:0F': 'TP-Link', '14:CC:20': 'TP-Link', '30:B5:C2': 'TP-Link',
    '50:C7:BF': 'TP-Link', '54:C8:0F': 'TP-Link', '60:E3:27': 'TP-Link',
    '98:DA:C4': 'TP-Link', 'A4:2B:B0': 'TP-Link', 'C0:25:E9': 'TP-Link',
    '00:14:6C': 'Netgear', '00:1B:2F': 'Netgear', '00:1E:2A': 'Netgear',
    '00:1F:33': 'Netgear', '04:A1:51': 'Netgear', '20:0C:C8': 'Netgear',
    '2C:B0:5D': 'Netgear', '6C:B0:CE': 'Netgear', 'C0:3F:0E': 'Netgear',
    '84:1B:5E': 'Netgear', 'A4:2B:8C': 'Netgear',
    'AC:84:C6': 'TP-Link', 'B0:BE:76': 'TP-Link',
    '00:1A:2B': 'Cisco', '00:22:BD': 'Cisco', '00:24:C3': 'Cisco',
    '64:00:6A': 'Dell', '18:03:73': 'Dell', '14:18:77': 'Dell',
    '3C:07:54': 'Apple', '68:DB:CA': 'Airtel',
    'E8:65:D4': 'Tenda', '48:A4:72': 'Sony',
    'CC:6D:A0': 'Roku', '98:8B:5D': 'Roku',
    'DC:A6:32': 'Raspberry Pi', 'E4:5F:01': 'Raspberry Pi',
    '00:1C:DF': 'Belkin', '08:86:3B': 'Belkin',
    'EC:08:6B': 'TP-Link', 'F4:EC:38': 'Espressif',
    '24:0A:C4': 'Espressif', '24:62:AB': 'Espressif',
    '30:AE:A4': 'Espressif', '84:CC:A8': 'Espressif',
    'A4:CF:12': 'Espressif', 'AC:67:B2': 'Espressif',
    'BC:DD:C2': 'Espressif', 'C4:4F:33': 'Espressif',
    '84:F3:EB': 'Espressif', 'A0:20:A6': 'Espressif',
    '10:52:1C': 'Espressif', '7C:DF:A1': 'Espressif',
    'D8:A0:1D': 'Espressif', '40:F5:20': 'Espressif',
    '8C:AA:B5': 'Espressif', '34:85:18': 'Espressif',
    '48:3F:DA': 'Espressif', 'E0:98:06': 'Espressif',
    'CC:50:E3': 'Espressif', '80:7D:3A': 'Espressif',
    '3C:61:05': 'Espressif', '3C:71:BF': 'Espressif',
    '78:E3:6D': 'Espressif', '34:B4:72': 'Espressif',
    '58:CF:79': 'Espressif'
};

function getVendor(mac) {
    if (!mac) return '';
    var prefix = mac.toUpperCase().substring(0, 8);
    return OUI_DB[prefix] || '';
}


// ============================================================
// Theme toggle (dark/light)
// ============================================================

function toggleTheme() {
    var body = document.body;
    var btn = document.getElementById('themeToggle');
    if (body.getAttribute('data-theme') === 'dark') {
        body.removeAttribute('data-theme');
        if (btn) btn.textContent = '🌙';
        localStorage.setItem('theme', 'light');
    } else {
        body.setAttribute('data-theme', 'dark');
        if (btn) btn.textContent = '☀️';
        localStorage.setItem('theme', 'dark');
    }
    // Update Chart.js colors if charts exist
    updateChartColors();
}

function updateChartColors() {
    var isDark = document.body.getAttribute('data-theme') === 'dark';
    var gridColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
    var tickColor = isDark ? '#a0a0b0' : '#666';
    [frameChart, channelChart].forEach(function(chart) {
        if (chart) {
            chart.options.scales.x.ticks.color = tickColor;
            chart.options.scales.y.ticks.color = tickColor;
            chart.options.scales.x.grid.color = gridColor;
            chart.options.scales.y.grid.color = gridColor;
            chart.update('none');
        }
    });
}

// Load saved theme on page load
(function() {
    if (localStorage.getItem('theme') === 'dark') {
        document.body.setAttribute('data-theme', 'dark');
        var btn = document.getElementById('themeToggle');
        if (btn) btn.textContent = '☀️';
    }
})();


// ============================================================
// Utility functions
// ============================================================

function formatTime(isoString) {
    if (!isoString) return '--';
    var d = new Date(isoString);
    var h = String(d.getHours()).padStart(2, '0');
    var m = String(d.getMinutes()).padStart(2, '0');
    var s = String(d.getSeconds()).padStart(2, '0');
    return h + ':' + m + ':' + s;
}

function formatMAC(mac) {
    if (!mac) return '--';
    return mac.toUpperCase();
}

function timeAgo(isoString) {
    if (!isoString) return '--';
    var diff = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
    if (diff < 5) return 'just now';
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    return Math.floor(diff / 3600) + 'h ago';
}

function severityBadgeHTML(severity) {
    var s = (severity || 'info').toLowerCase();
    return '<span class="severity-badge ' + s + '">' + s.toUpperCase() + '</span>';
}

function severityClass(severity) {
    var s = (severity || 'info').toLowerCase();
    return 'severity-' + s;
}


// ============================================================
// Connection status
// ============================================================

function setConnected(connected) {
    var el = document.getElementById('connectionStatus');
    if (connected) {
        el.innerHTML = '<span class="dot dot-green"></span><span>Connected</span>';
    } else {
        el.innerHTML = '<span class="dot dot-red"></span><span>Disconnected</span>';
    }
}


// ============================================================
// Threat level display
// ============================================================

function updateThreatLevel(level) {
    var el = document.getElementById('threatLevel');
    var text = (level || 'SAFE').toUpperCase();
    el.textContent = text;

    // remove old classes
    el.className = 'threat-badge';
    if (text === 'CRITICAL') el.classList.add('threat-critical');
    else if (text === 'HIGH') el.classList.add('threat-high');
    else if (text === 'WARNING') el.classList.add('threat-warning');
    else el.classList.add('threat-safe');
}

function scoreClass(score) {
    if (score >= 75) return 'device-score-critical';
    if (score >= 50) return 'device-score-high';
    if (score >= 25) return 'device-score-warning';
    return 'device-score-safe';
}

function scoreHTML(mac) {
    var s = deviceScores[mac] || 0;
    var reasons = deviceReasons[mac] || [];
    var html = '<span class="device-score ' + scoreClass(s) + '" onclick="showBaseline(\'' + mac + '\')" style="cursor:pointer" title="Click for details">' + s + '</span>';
    if (reasons.length > 0 && reasons[0] !== 'Normal behavior' && reasons[0] !== 'Building baseline... (need more data)') {
        var reasonText = reasons.join('&#10;');
        html += ' <span class="risk-why" title="' + reasonText + '">Why?</span>';
    } else if (reasons.length > 0 && reasons[0] === 'Building baseline... (need more data)') {
        html += ' <span class="risk-building">⏳</span>';
    }
    return html;
}

function showBaseline(mac) {
    fetch('/api/device-baseline/' + mac)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.error) {
                alert(data.error);
                return;
            }
            var b = data.baseline;
            var c = data.current;
            var vendor = getVendor(mac);
            var title = formatMAC(mac) + (vendor ? ' (' + vendor + ')' : '');

            // Build comparison table
            var html = '<div class="baseline-modal-overlay" onclick="this.remove()">';
            html += '<div class="baseline-modal" onclick="event.stopPropagation()">';
            html += '<div class="baseline-header">';
            html += '<h3>' + title + '</h3>';
            html += '<span class="device-score ' + scoreClass(data.risk_score) + '">Risk: ' + data.risk_score + '</span>';
            html += '<button class="baseline-close" onclick="this.closest(\'.baseline-modal-overlay\').remove()">✕</button>';
            html += '</div>';

            // Reasons
            if (data.reasons && data.reasons.length > 0 && data.reasons[0] !== 'Normal behavior') {
                html += '<div class="baseline-reasons">';
                for (var i = 0; i < data.reasons.length; i++) {
                    html += '<div class="baseline-reason">⚠ ' + data.reasons[i] + '</div>';
                }
                html += '</div>';
            }

            // Comparison table
            html += '<table class="baseline-table">';
            html += '<tr><th>Metric</th><th>Baseline (Normal)</th><th>Current (Last 5 min)</th></tr>';

            html += '<tr><td>Packet Count / 5min</td>';
            html += '<td>' + b.pkt_rate_avg + ' ± ' + b.pkt_rate_std + '</td>';
            html += '<td>' + c.pkt_count + '</td></tr>';

            html += '<tr><td>Destinations</td>';
            html += '<td>' + b.dest_avg + ' avg (' + b.known_dests_count + ' known)</td>';
            html += '<td>' + c.dest_count + '</td></tr>';

            html += '<tr><td>Channels</td>';
            html += '<td>' + b.chan_avg + ' avg</td>';
            html += '<td>' + c.chan_count + '</td></tr>';

            html += '<tr><td>Active Hours</td>';
            var hours = b.active_hours.map(function(h) { return h + ':00'; }).join(', ');
            html += '<td style="font-size:11px">' + (hours || 'N/A') + '</td>';
            html += '<td>' + c.hour + ':00</td></tr>';

            // Frame distribution
            var allFt = {};
            for (var ft in b.frame_dist) allFt[ft] = true;
            for (var ft2 in c.frame_dist) allFt[ft2] = true;
            for (var ft3 in allFt) {
                html += '<tr><td>Frame: ' + ft3 + '</td>';
                html += '<td>' + (b.frame_dist[ft3] || 0) + '%</td>';
                html += '<td>' + (c.frame_dist[ft3] || 0) + '%</td></tr>';
            }

            html += '</table>';
            html += '<p class="baseline-meta">Total events: ' + data.total_events + ' | First seen: ' + (data.first_seen || 'N/A') + '</p>';
            html += '</div></div>';

            // Remove existing modal
            var existing = document.querySelector('.baseline-modal-overlay');
            if (existing) existing.remove();

            document.body.insertAdjacentHTML('beforeend', html);
        })
        .catch(function(e) { console.error('Failed to load baseline:', e); });
}


// ============================================================
// Stats cards
// ============================================================

function updateStats(stats) {
    document.getElementById('statTotalFrames').textContent = stats.total_events || 0;

    var alertsEl = document.getElementById('statActiveAlerts');
    alertsEl.textContent = stats.active_alerts || 0;
    if ((stats.active_alerts || 0) > 0) {
        alertsEl.classList.add('has-alerts');
    } else {
        alertsEl.classList.remove('has-alerts');
    }

    document.getElementById('statUniqueDevices').textContent = stats.unique_devices || 0;

    updateThreatLevel(stats.threat_level);
}


// ============================================================
// Charts
// ============================================================

function initFrameChart() {
    var ctx = document.getElementById('frameChart').getContext('2d');
    frameChart = new Chart(ctx, {
        type: 'line',
        data: {
            datasets: [
                {
                    label: 'DEAUTH',
                    data: [],
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220,53,69,0.1)',
                    borderWidth: 2,
                    pointRadius: 0,
                    tension: 0.2,
                    fill: false
                },
                {
                    label: 'BEACON',
                    data: [],
                    borderColor: '#0d6efd',
                    backgroundColor: 'rgba(13,110,253,0.1)',
                    borderWidth: 2,
                    pointRadius: 0,
                    tension: 0.2,
                    fill: false
                },
                {
                    label: 'PROBE_REQ',
                    data: [],
                    borderColor: '#28a745',
                    backgroundColor: 'rgba(40,167,69,0.1)',
                    borderWidth: 2,
                    pointRadius: 0,
                    tension: 0.2,
                    fill: false
                },
                {
                    label: 'DISASSOC',
                    data: [],
                    borderColor: '#fd7e14',
                    backgroundColor: 'rgba(253,126,20,0.1)',
                    borderWidth: 2,
                    pointRadius: 0,
                    tension: 0.2,
                    fill: false
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                x: {
                    type: 'time',
                    time: {
                        unit: 'second',
                        displayFormats: { second: 'HH:mm:ss' },
                        tooltipFormat: 'HH:mm:ss'
                    },
                    title: { display: false },
                    grid: { color: '#f0f0f0' },
                    ticks: { maxTicksLimit: 8, font: { size: 11 } }
                },
                y: {
                    beginAtZero: true,
                    title: { display: true, text: 'Frames/sec', font: { size: 12 } },
                    grid: { color: '#f0f0f0' },
                    ticks: { font: { size: 11 } }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: { boxWidth: 12, font: { size: 11 } }
                }
            }
        }
    });
}

function initChannelChart() {
    var ctx = document.getElementById('channelChart').getContext('2d');
    channelChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Frames',
                data: [],
                backgroundColor: [],
                borderWidth: 1,
                borderColor: '#e0e0e0'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                x: {
                    title: { display: true, text: 'Channel', font: { size: 12 } },
                    grid: { display: false },
                    ticks: { font: { size: 11 } }
                },
                y: {
                    beginAtZero: true,
                    title: { display: true, text: 'Frames', font: { size: 12 } },
                    grid: { color: '#f0f0f0' },
                    ticks: { font: { size: 11 } }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

// push per-second counters into the frame chart (called every 1s)
function pushFrameChartTick() {
    var now = new Date();
    var datasetMap = { DEAUTH: 0, BEACON: 1, PROBE_REQ: 2, DISASSOC: 3 };

    for (var type in datasetMap) {
        var idx = datasetMap[type];
        frameChart.data.datasets[idx].data.push({
            x: now,
            y: frameCounters[type]
        });
        // trim old points
        if (frameChart.data.datasets[idx].data.length > MAX_CHART_POINTS) {
            frameChart.data.datasets[idx].data.shift();
        }
    }

    // reset counters
    frameCounters = { DEAUTH: 0, BEACON: 0, PROBE_REQ: 0, DISASSOC: 0 };

    frameChart.update('none');
}

function getChannelColor(ch) {
    // 2.4 GHz channels: 1-14, 5 GHz: everything else
    var channel = parseInt(ch, 10);
    if (channel >= 1 && channel <= 14) return '#0d6efd';
    return '#6f42c1';
}

function updateChannelChart() {
    var channels = Object.keys(channelCounts).map(Number).sort(function(a, b) { return a - b; });
    var labels = channels.map(String);
    var data = channels.map(function(ch) { return channelCounts[ch]; });
    var colors = channels.map(function(ch) { return getChannelColor(ch); });

    channelChart.data.labels = labels;
    channelChart.data.datasets[0].data = data;
    channelChart.data.datasets[0].backgroundColor = colors;
    channelChart.update('none');
}


// ============================================================
// Alert Feed
// ============================================================

function renderAlertFeed() {
    var container = document.getElementById('alertFeed');

    if (alertList.length === 0) {
        container.innerHTML = '<p class="empty-msg">No alerts yet.</p>';
        return;
    }

    var html = '';
    for (var i = 0; i < alertList.length; i++) {
        var a = alertList[i];
        var sev = (a.severity || 'info').toLowerCase();
        var acked = a.acknowledged ? ' acknowledged' : '';
        html += '<div class="alert-item ' + severityClass(a.severity) + acked + '" data-id="' + (a.id || '') + '">';
        html += '  <div class="alert-info">';
        html += '    <div class="alert-header">';
        html += '      <span class="alert-time">' + formatTime(a.timestamp || a.created_at) + '</span>';
        html += '      ' + severityBadgeHTML(a.severity);
        html += '      <span class="alert-type">' + (a.alert_type || a.type || '') + '</span>';
        html += '    </div>';
        html += '    <div class="alert-desc">' + (a.description || '') + '</div>';
        if (a.source_mac) {
            html += '    <div class="alert-mac">Source: ' + formatMAC(a.source_mac) + '</div>';
        }
        html += '  </div>';
        if (a.id && !a.acknowledged) {
            html += '  <div class="alert-actions">';
            html += '    <button class="btn btn-sm" onclick="acknowledgeAlert(\'' + a.id + '\')">Ack</button>';
            html += '  </div>';
        }
        html += '</div>';
    }

    container.innerHTML = html;
}

function addAlert(alert) {
    alertList.unshift(alert);
    if (alertList.length > MAX_ALERTS) {
        alertList.pop();
    }
    renderAlertFeed();
}

function acknowledgeAlert(alertId) {
    fetch('/api/alerts/' + alertId + '/acknowledge', { method: 'PUT' })
        .then(function(resp) {
            if (resp.ok) {
                // mark it locally
                for (var i = 0; i < alertList.length; i++) {
                    if (alertList[i].id === alertId) {
                        alertList[i].acknowledged = true;
                        break;
                    }
                }
                renderAlertFeed();
            }
        })
        .catch(function(err) {
            console.error('Failed to acknowledge alert:', err);
        });
}


// ============================================================
// Device Table
// ============================================================

function sortDevices(col) {
    if (deviceSort.col === col) {
        deviceSort.dir = deviceSort.dir === 'asc' ? 'desc' : 'asc';
    } else {
        deviceSort.col = col;
        deviceSort.dir = (col === 'score' || col === 'last_seen') ? 'desc' : 'asc';
    }
    renderDeviceTable(true);
}

function renderDeviceTable(forceRebuild) {
    var tbody = document.querySelector('#deviceTable tbody');
    var macs = Object.keys(devices);

    if (macs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-msg">No devices detected.</td></tr>';
        return;
    }

    // Update sort indicators in header
    var ths = document.querySelectorAll('#deviceTable thead th[data-sort]');
    for (var t = 0; t < ths.length; t++) {
        var arrow = ths[t].querySelector('.sort-arrow');
        if (arrow) arrow.remove();
        if (ths[t].getAttribute('data-sort') === deviceSort.col) {
            var span = document.createElement('span');
            span.className = 'sort-arrow';
            span.textContent = deviceSort.dir === 'asc' ? ' ▲' : ' ▼';
            ths[t].appendChild(span);
        }
    }

    // Check if structure changed
    var existingRows = tbody.querySelectorAll('tr[data-mac]');
    var existingMacs = {};
    for (var r = 0; r < existingRows.length; r++) {
        existingMacs[existingRows[r].getAttribute('data-mac')] = existingRows[r];
    }

    var needsFullRebuild = forceRebuild || false;
    if (!needsFullRebuild) {
        if (Object.keys(existingMacs).length !== macs.length) {
            needsFullRebuild = true;
        } else {
            for (var m = 0; m < macs.length; m++) {
                var row = existingMacs[macs[m]];
                if (!row) { needsFullRebuild = true; break; }
                var dev = devices[macs[m]];
                var rowStatus = row.querySelector('.status-known') ? true : false;
                var devWhitelisted = dev.is_whitelisted || dev.status === 'Known';
                if (rowStatus !== devWhitelisted) { needsFullRebuild = true; break; }
            }
        }
    }

    // In-place update for score + last seen
    if (!needsFullRebuild && existingRows.length > 0) {
        for (var u = 0; u < existingRows.length; u++) {
            var rowMac = existingRows[u].getAttribute('data-mac');
            var dev = devices[rowMac];
            if (dev) {
                var cells = existingRows[u].querySelectorAll('td');
                if (cells.length >= 6) {
                    cells[4].innerHTML = scoreHTML(rowMac);
                    cells[5].textContent = timeAgo(dev.last_seen);
                }
            }
        }
        return;
    }

    // Sort macs by current sort column
    macs.sort(function(a, b) {
        var va, vb;
        switch (deviceSort.col) {
            case 'mac':      va = a; vb = b; break;
            case 'vendor':   va = getVendor(a); vb = getVendor(b); break;
            case 'status':
                va = (devices[a].is_whitelisted || devices[a].status === 'Known') ? 0 : 1;
                vb = (devices[b].is_whitelisted || devices[b].status === 'Known') ? 0 : 1;
                break;
            case 'score':    va = deviceScores[a] || 0; vb = deviceScores[b] || 0; break;
            case 'last_seen':
                va = new Date(devices[a].last_seen || 0).getTime();
                vb = new Date(devices[b].last_seen || 0).getTime();
                break;
            default:         va = a; vb = b;
        }
        if (va < vb) return deviceSort.dir === 'asc' ? -1 : 1;
        if (va > vb) return deviceSort.dir === 'asc' ? 1 : -1;
        return 0;
    });

    var html = '';
    for (var i = 0; i < macs.length; i++) {
        var d = devices[macs[i]];
        var mac = macs[i];
        var vendor = getVendor(mac);
        var name = d.device_name || d.name || '';
        var displayName = vendor || name || '--';
        var isKnown = d.is_whitelisted || d.status === 'Known';
        var statusClass = isKnown ? 'status-known' : 'status-unknown';
        var statusText = isKnown ? 'Known' : 'Unknown';
        var lastSeen = timeAgo(d.last_seen);

        html += '<tr data-mac="' + mac + '">';
        html += '<td class="mac">' + formatMAC(mac) + '</td>';
        html += '<td>' + displayName + (vendor && name ? ' <span class="meta-dim">(' + name + ')</span>' : '') + '</td>';
        html += '<td class="' + statusClass + '">' + statusText + '</td>';
        html += '<td>' + scoreHTML(mac) + '</td>';
        html += '<td>' + lastSeen + '</td>';
        html += '<td>';
        if (!isKnown) {
            html += '<button class="btn btn-sm btn-success" onclick="addToWhitelist(\'' + mac + '\')">Whitelist</button>';
        } else {
            html += '<button class="btn btn-sm btn-danger" onclick="removeFromWhitelist(\'' + mac + '\')">Remove</button>';
        }
        html += '</td>';
        html += '</tr>';
    }

    tbody.innerHTML = html;
}

function addToWhitelist(mac) {
    var name = prompt('Enter a name for this device (optional):', '');
    if (name === null) return; // cancelled

    fetch('/api/whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac_address: mac, device_name: name || 'Unknown Device' })
    })
    .then(function(resp) {
        if (resp.ok) {
            if (devices[mac]) {
                devices[mac].is_whitelisted = true;
                devices[mac].device_name = name || 'Unknown Device';
            }
            renderDeviceTable();
        }
    })
    .catch(function(err) {
        console.error('Failed to whitelist device:', err);
    });
}

function removeFromWhitelist(mac) {
    fetch('/api/whitelist/' + encodeURIComponent(mac), { method: 'DELETE' })
        .then(function(resp) {
            if (resp.ok) {
                if (devices[mac]) {
                    devices[mac].is_whitelisted = false;
                    devices[mac].device_name = '';
                }
                renderDeviceTable();
            }
        })
        .catch(function(err) {
            console.error('Failed to remove from whitelist:', err);
        });
}


// ============================================================
// Access Points Table
// ============================================================

function renderAPTable() {
    var tbody = document.querySelector('#apTable tbody');
    var bssids = Object.keys(accessPoints);

    if (bssids.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-msg">No access points detected.</td></tr>';
        return;
    }

    // Check if structure changed (new AP or trust status changed)
    var existingRows = tbody.querySelectorAll('tr[data-bssid]');
    var existingBssids = {};
    for (var r = 0; r < existingRows.length; r++) {
        existingBssids[existingRows[r].getAttribute('data-bssid')] = existingRows[r];
    }

    var needsFullRebuild = false;
    if (Object.keys(existingBssids).length !== bssids.length) {
        needsFullRebuild = true;
    } else {
        for (var m = 0; m < bssids.length; m++) {
            var row = existingBssids[bssids[m]];
            if (!row) { needsFullRebuild = true; break; }
            // Check if trust status changed
            var apCheck = accessPoints[bssids[m]];
            var rowTrusted = row.querySelector('.status-trusted') ? true : false;
            var apTrusted = (apCheck.status || '').toLowerCase() === 'trusted';
            if (rowTrusted !== apTrusted) { needsFullRebuild = true; break; }
        }
    }

    // If no structural change, just update RSSI in place
    if (!needsFullRebuild && existingRows.length > 0) {
        for (var u = 0; u < existingRows.length; u++) {
            var rowBssid = existingRows[u].getAttribute('data-bssid');
            var apData = accessPoints[rowBssid];
            if (apData) {
                var cells = existingRows[u].querySelectorAll('td');
                if (cells.length >= 5) {
                    cells[2].textContent = apData.channel || '--';
                    cells[3].textContent = apData.rssi != null ? apData.rssi + ' dBm' : '--';
                }
            }
        }
        return;
    }

    // Full rebuild (only when a new AP appears or trust status changes)
    bssids.sort(function(a, b) {
        var ap1 = accessPoints[a];
        var ap2 = accessPoints[b];
        var s1 = (ap1.status || '').toLowerCase();
        var s2 = (ap2.status || '').toLowerCase();
        if (s1 === 'rogue' && s2 !== 'rogue') return -1;
        if (s2 === 'rogue' && s1 !== 'rogue') return 1;
        return (ap1.ssid || '').localeCompare(ap2.ssid || '');
    });

    var html = '';
    for (var i = 0; i < bssids.length; i++) {
        var ap = accessPoints[bssids[i]];
        var bssid = bssids[i];
        var status = ap.status || 'Unknown';
        var statusLower = status.toLowerCase();
        var statusClass = '';
        var rowClass = '';
        var isHidden = !ap.ssid || ap.ssid.trim() === '';
        var displaySSID = isHidden ? '<span class="hidden-network">Hidden Network</span>' : ap.ssid;

        if (statusLower === 'trusted') statusClass = 'status-trusted';
        else if (statusLower === 'rogue') { statusClass = 'status-rogue'; rowClass = 'row-rogue'; }
        else statusClass = 'status-unknown';

        html += '<tr data-bssid="' + bssid + '" class="' + rowClass + '">';
        html += '<td>' + displaySSID + '</td>';
        html += '<td class="mac">' + formatMAC(bssid) + '</td>';
        html += '<td>' + (ap.channel || '--') + '</td>';
        html += '<td>' + (ap.rssi != null ? ap.rssi + ' dBm' : '--') + '</td>';
        html += '<td>' + (ap.band || '--') + '</td>';
        html += '<td class="' + statusClass + '">' + status + '</td>';
        html += '<td>';
        if (statusLower === 'trusted') {
            html += '<button class="btn btn-sm btn-danger" onclick="untrustAP(\'' + bssid + '\')">Untrust</button>';
        } else {
            html += '<button class="btn btn-sm btn-primary" onclick="trustAP(\'' + bssid + '\',\'' + (ap.ssid || '') + '\',' + (ap.channel || 0) + ')">Trust</button>';
        }
        html += '</td>';
        html += '</tr>';
    }

    tbody.innerHTML = html;
}

function trustAP(bssid, ssid, channel) {
    fetch('/api/trusted-aps', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ssid: ssid, bssid: bssid, expected_channel: channel })
    })
    .then(function(resp) {
        if (resp.ok) {
            if (accessPoints[bssid]) {
                accessPoints[bssid].status = 'Trusted';
            }
            renderAPTable();
        }
    })
    .catch(function(err) {
        console.error('Failed to trust AP:', err);
    });
}

function untrustAP(bssid) {
    fetch('/api/trusted-aps/' + encodeURIComponent(bssid), { method: 'DELETE' })
        .then(function(resp) {
            if (resp.ok) {
                if (accessPoints[bssid]) {
                    accessPoints[bssid].status = 'Unknown';
                }
                renderAPTable();
            }
        })
        .catch(function(err) {
            console.error('Failed to untrust AP:', err);
        });
}


// ============================================================
// WebSocket
// ============================================================

function connectWebSocket() {
    var protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    var url = protocol + '//' + location.host + '/ws';

    console.log('Connecting to WebSocket:', url);
    ws = new WebSocket(url);

    ws.onopen = function() {
        console.log('WebSocket connected');
        setConnected(true);
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
        }
    };

    ws.onclose = function() {
        console.log('WebSocket disconnected');
        setConnected(false);
        scheduleReconnect();
    };

    ws.onerror = function(err) {
        console.error('WebSocket error:', err);
        ws.close();
    };

    ws.onmessage = function(event) {
        try {
            var msg = JSON.parse(event.data);
            handleWSMessage(msg);
        } catch (e) {
            console.error('Failed to parse WS message:', e);
        }
    };
}

function scheduleReconnect() {
    if (reconnectTimer) return;
    reconnectTimer = setTimeout(function() {
        reconnectTimer = null;
        connectWebSocket();
    }, 3000);
}

function handleWSMessage(msg) {
    if (msg.type === 'new_event') {
        handleNewEvent(msg.event, msg.alerts);
    } else if (msg.type === 'stats_update') {
        updateStats(msg.stats);
    } else if (msg.type === 'behavior_update') {
        handleBehaviorUpdate(msg.risks);
    }
}

function handleBehaviorUpdate(risks) {
    if (!risks) return;
    for (var mac in risks) {
        deviceScores[mac] = risks[mac].risk_score || 0;
        deviceReasons[mac] = risks[mac].reasons || [];
    }
    deviceTableDirty = true;
}

function handleNewEvent(event, alerts) {
    if (!event) return;

    // count frame type for chart
    var ft = (event.frame_type || '').toUpperCase();
    if (frameCounters.hasOwnProperty(ft)) {
        frameCounters[ft]++;
    }

    // update channel counts
    if (event.channel) {
        var ch = event.channel;
        channelCounts[ch] = (channelCounts[ch] || 0) + 1;
        updateChannelChart();
    }

    // track device — mark dirty instead of immediate render
    if (event.src_mac) {
        var mac = event.src_mac;
        if (!devices[mac]) {
            devices[mac] = {
                mac_address: mac,
                device_name: '',
                is_whitelisted: false,
                last_seen: event.timestamp
            };
        } else {
            devices[mac].last_seen = event.timestamp;
        }
        deviceTableDirty = true;
    }

    // track AP from beacon frames — mark dirty instead of immediate render
    if (event.bssid && (ft === 'BEACON' || ft === 'PROBE_RESP')) {
        var bssid = event.bssid;
        if (!accessPoints[bssid]) {
            accessPoints[bssid] = {
                ssid: event.ssid || '',
                bssid: bssid,
                channel: event.channel,
                rssi: event.rssi,
                band: event.band || '',
                status: 'Unknown'
            };
        } else {
            if (event.rssi != null) accessPoints[bssid].rssi = event.rssi;
            if (event.channel) accessPoints[bssid].channel = event.channel;
            if (event.ssid) accessPoints[bssid].ssid = event.ssid;
            if (event.band) accessPoints[bssid].band = event.band;
        }
        apTableDirty = true;
    }

    // process alerts and update per-device scores
    if (alerts && alerts.length > 0) {
        for (var i = 0; i < alerts.length; i++) {
            addAlert(alerts[i]);
            // Increment per-device score
            var alertMac = alerts[i].source_mac;
            if (alertMac) {
                var newScore = (deviceScores[alertMac] || 0) + (alerts[i].threat_score || 0);
                deviceScores[alertMac] = Math.min(newScore, 100);
                deviceTableDirty = true;
            }
        }
    }
}


// ============================================================
// Simulator Controls
// ============================================================

var simRunning = false;

function sendSimCommand(scenario) {
    // Update button states
    var btns = document.querySelectorAll('.btn-sim');
    if (scenario === 'stop') {
        simRunning = false;
        for (var i = 0; i < btns.length; i++) btns[i].classList.remove('btn-active');
    } else {
        simRunning = true;
        for (var i = 0; i < btns.length; i++) btns[i].classList.remove('btn-active');
        event.target.classList.add('btn-active');
    }

    fetch('/api/simulator/' + scenario, { method: 'POST' })
        .then(function(resp) { return resp.json(); })
        .then(function(data) {
            if (data.error) {
                console.error('Simulator:', data.error);
            }
        })
        .catch(function(err) {
            console.error('Simulator error:', err);
        });
}


// ============================================================
// Initial Data Load
// ============================================================

function loadInitialData() {
    // load stats
    fetch('/api/stats')
        .then(function(r) { return r.json(); })
        .then(function(data) { updateStats(data); })
        .catch(function(e) { console.warn('Could not load stats:', e); });

    // load alerts
    fetch('/api/alerts?limit=50')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var list = Array.isArray(data) ? data : (data.alerts || []);
            alertList = list;
            renderAlertFeed();
        })
        .catch(function(e) { console.warn('Could not load alerts:', e); });

    // load devices
    fetch('/api/devices')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var list = Array.isArray(data) ? data : (data.devices || []);
            for (var i = 0; i < list.length; i++) {
                var d = list[i];
                var mac = d.mac_address || d.mac;
                if (mac) {
                    devices[mac] = d;
                }
            }
            renderDeviceTable();
        })
        .catch(function(e) { console.warn('Could not load devices:', e); });

    // load access points
    fetch('/api/access-points')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var list = Array.isArray(data) ? data : (data.access_points || []);
            for (var i = 0; i < list.length; i++) {
                var ap = list[i];
                var bssid = ap.bssid;
                if (bssid) {
                    accessPoints[bssid] = ap;
                }
            }
            renderAPTable();
        })
        .catch(function(e) { console.warn('Could not load access points:', e); });

    // load per-device risk scores + reasons from behavior profiler
    fetch('/api/device-risks')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            for (var mac in data) {
                deviceScores[mac] = data[mac].risk_score || 0;
                deviceReasons[mac] = data[mac].reasons || [];
            }
            renderDeviceTable();
        })
        .catch(function(e) { console.warn('Could not load device risks:', e); });
}


// ============================================================
// Periodic refresh of "last seen" times
// ============================================================

// Flush dirty tables on a 2-second timer so buttons stay clickable
function startTableFlush() {
    setInterval(function() {
        if (deviceTableDirty) {
            renderDeviceTable();
            deviceTableDirty = false;
        }
        if (apTableDirty) {
            renderAPTable();
            apTableDirty = false;
        }
    }, 2000);
}

// Poll stats every 5 seconds so the top cards stay current
function startStatsPoller() {
    setInterval(function() {
        fetch('/api/stats')
            .then(function(r) { return r.json(); })
            .then(function(data) { updateStats(data); })
            .catch(function() {});
    }, 5000);
}


// ============================================================
// Init
// ============================================================

document.addEventListener('DOMContentLoaded', function() {
    // set up charts
    initFrameChart();
    initChannelChart();

    // start chart tick (1 data point per second)
    chartTickInterval = setInterval(pushFrameChartTick, 1000);

    // load existing data
    loadInitialData();

    // connect websocket
    connectWebSocket();

    // flush dirty tables every 2s (keeps buttons stable)
    startTableFlush();

    // poll stats every 5s so top cards update
    startStatsPoller();
});
