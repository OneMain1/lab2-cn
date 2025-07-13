// WiFi Traffic Monitor - Main JavaScript Application

// Global Variables
let realtimeUpdateInterval = null;
let isRealtimeEnabled = false;

// Initialize Application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Initialize tooltips
    initializeTooltips();
    
    // Setup real-time updates
    setupRealtimeUpdates();
    
    // Setup event listeners
    setupEventListeners();
    
    // Initialize charts if on dashboard
    if (window.location.pathname === '/dashboard') {
        initializeDashboardCharts();
    }
    
    console.log('WiFi Traffic Monitor initialized');
}

function initializeTooltips() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

function setupRealtimeUpdates() {
    // Enable real-time updates on dashboard and traffic pages
    if (window.location.pathname === '/dashboard' || window.location.pathname === '/traffic') {
        startRealtimeUpdates();
    }
}

function setupEventListeners() {
    // Global event listeners
    
    // Auto-refresh toggle
    const autoRefreshBtn = document.getElementById('autoRefresh');
    if (autoRefreshBtn) {
        autoRefreshBtn.addEventListener('click', toggleAutoRefresh);
    }
    
    // Export functionality
    const exportBtn = document.getElementById('exportData');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportData);
    }
    
    // Filter forms
    const filterForm = document.getElementById('filterForm');
    if (filterForm) {
        filterForm.addEventListener('submit', handleFilterSubmit);
    }
    
    // Clear filters
    const clearFiltersBtn = document.getElementById('clearFilters');
    if (clearFiltersBtn) {
        clearFiltersBtn.addEventListener('click', clearFilters);
    }
}

function startRealtimeUpdates() {
    if (realtimeUpdateInterval) {
        clearInterval(realtimeUpdateInterval);
    }
    
    realtimeUpdateInterval = setInterval(updateRealtimeData, 30000); // 30 seconds
    isRealtimeEnabled = true;
    
    console.log('Real-time updates started');
}

function stopRealtimeUpdates() {
    if (realtimeUpdateInterval) {
        clearInterval(realtimeUpdateInterval);
        realtimeUpdateInterval = null;
    }
    
    isRealtimeEnabled = false;
    console.log('Real-time updates stopped');
}

function updateRealtimeData() {
    fetch('/api/realtime_stats')
        .then(response => response.json())
        .then(data => {
            updateDashboardStats(data);
            updateCaptureStatus(data.capture_running);
            
            // Update last update time
            const lastUpdate = document.getElementById('lastUpdate');
            if (lastUpdate) {
                lastUpdate.textContent = new Date().toLocaleTimeString();
            }
        })
        .catch(error => {
            console.error('Error updating real-time data:', error);
        });
}

function updateDashboardStats(data) {
    // Update active devices count
    if (data.top_sources && document.getElementById('activeDevices')) {
        document.getElementById('activeDevices').textContent = data.top_sources.length;
    }
    
    // Update recent activity
    if (data.recent_activity) {
        updateRecentActivity(data.recent_activity);
    }
}

function updateRecentActivity(activity) {
    const tableBody = document.getElementById('recentActivityTable');
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    activity.forEach(item => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><span class="badge bg-${getProtocolColor(item._id)}">${item._id}</span></td>
            <td>${item.count}</td>
            <td>${formatBytes(item.total_bytes)}</td>
        `;
        tableBody.appendChild(row);
    });
}

function updateCaptureStatus(isRunning) {
    const statusElement = document.getElementById('captureStatus');
    const toggleButton = document.getElementById('toggleCapture');
    
    if (statusElement) {
        if (isRunning) {
            statusElement.innerHTML = '<i class="fas fa-circle text-success"></i> Active';
        } else {
            statusElement.innerHTML = '<i class="fas fa-circle text-danger"></i> Stopped';
        }
    }
    
    if (toggleButton) {
        updateCaptureButton(isRunning);
    }
}

function updateCaptureButton(isRunning) {
    const button = document.getElementById('toggleCapture');
    if (!button) return;
    
    if (isRunning) {
        button.className = 'btn btn-outline-danger';
        button.innerHTML = '<i class="fas fa-stop"></i> Stop Capture';
    } else {
        button.className = 'btn btn-outline-success';
        button.innerHTML = '<i class="fas fa-play"></i> Start Capture';
    }
}

function toggleAutoRefresh() {
    const button = document.getElementById('autoRefresh');
    
    if (isRealtimeEnabled) {
        stopRealtimeUpdates();
        button.innerHTML = '<i class="fas fa-sync-alt"></i> Auto Refresh: Off';
        button.className = 'btn btn-sm btn-outline-primary';
    } else {
        startRealtimeUpdates();
        button.innerHTML = '<i class="fas fa-sync-alt"></i> Auto Refresh: On';
        button.className = 'btn btn-sm btn-success';
    }
}

function exportData() {
    // Get current filter parameters
    const protocol = document.getElementById('protocolFilter')?.value || '';
    const srcIp = document.getElementById('srcIpFilter')?.value || '';
    const destIp = document.getElementById('destIpFilter')?.value || '';
    
    const params = new URLSearchParams({
        page: 1,
        limit: 10000 // Large limit for export
    });
    
    if (protocol) params.append('protocol', protocol);
    if (srcIp) params.append('src_ip', srcIp);
    if (destIp) params.append('dest_ip', destIp);
    
    // Show loading
    const exportBtn = document.getElementById('exportData');
    const originalText = exportBtn.innerHTML;
    exportBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Exporting...';
    exportBtn.disabled = true;
    
    fetch(`/api/packets?${params}`)
        .then(response => response.json())
        .then(data => {
            const csv = convertToCSV(data.packets);
            downloadCSV(csv, `traffic_export_${new Date().toISOString().split('T')[0]}.csv`);
        })
        .catch(error => {
            console.error('Error exporting data:', error);
            alert('Error exporting data');
        })
        .finally(() => {
            exportBtn.innerHTML = originalText;
            exportBtn.disabled = false;
        });
}

function convertToCSV(packets) {
    const headers = [
        'Timestamp', 'Source IP', 'Source Port', 'Destination IP', 
        'Destination Port', 'Protocol', 'Size (Bytes)', 'URL/DNS', 'Packet ID'
    ];
    
    const csvData = [headers.join(',')];
    
    packets.forEach(packet => {
        const row = [
            `"${packet.timestamp}"`,
            `"${packet.src_ip || ''}"`,
            `"${packet.src_port || ''}"`,
            `"${packet.dest_ip || ''}"`,
            `"${packet.dest_port || ''}"`,
            `"${packet.protocol || ''}"`,
            packet.packet_length || 0,
            `"${(packet.url || packet.dns_query || '').replace(/"/g, '""')}"`,
            `"${packet.packet_id || ''}"`
        ];
        csvData.push(row.join(','));
    });
    
    return csvData.join('\n');
}

function downloadCSV(csv, filename) {
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    
    if (link.download !== undefined) {
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', filename);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
}

function handleFilterSubmit(event) {
    event.preventDefault();
    
    // Reload data with new filters
    if (typeof loadPackets === 'function') {
        loadPackets();
    }
}

function clearFilters() {
    // Clear all filter inputs
    const filterInputs = document.querySelectorAll('#filterForm input, #filterForm select');
    filterInputs.forEach(input => {
        if (input.type === 'select-one') {
            input.selectedIndex = 0;
        } else {
            input.value = '';
        }
    });
    
    // Reload data
    if (typeof loadPackets === 'function') {
        loadPackets();
    }
}

function initializeDashboardCharts() {
    // Chart initialization is handled in the dashboard template
    console.log('Dashboard charts initialization completed');
}

// Utility Functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function getProtocolColor(protocol) {
    const colors = {
        'TCP': 'primary',
        'UDP': 'success',
        'ICMP': 'warning',
        'HTTP': 'info',
        'HTTPS': 'secondary',
        'DNS': 'dark'
    };
    return colors[protocol] || 'secondary';
}

function showLoading(elementId, show = true) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    if (show) {
        element.innerHTML = '<div class="text-center"><div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div></div>';
    }
}

function hideLoading(elementId) {
    showLoading(elementId, false);
}

// Error Handling
function showError(message, type = 'error') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const container = document.querySelector('.container-fluid');
    if (container) {
        container.insertBefore(alertDiv, container.firstChild);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
}

function showSuccess(message) {
    showError(message, 'success');
}

// API Helper Functions
function apiCall(endpoint, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
    };
    
    const mergedOptions = { ...defaultOptions, ...options };
    
    return fetch(endpoint, mergedOptions)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .catch(error => {
            console.error('API call failed:', error);
            throw error;
        });
}

// Keyboard Shortcuts
document.addEventListener('keydown', function(event) {
    // Ctrl+R: Refresh data
    if (event.ctrlKey && event.key === 'r') {
        event.preventDefault();
        location.reload();
    }
    
    // Ctrl+E: Export data
    if (event.ctrlKey && event.key === 'e') {
        event.preventDefault();
        const exportBtn = document.getElementById('exportData');
        if (exportBtn) {
            exportBtn.click();
        }
    }
    
    // Esc: Clear filters
    if (event.key === 'Escape') {
        const clearBtn = document.getElementById('clearFilters');
        if (clearBtn) {
            clearBtn.click();
        }
    }
});

// Page Visibility API - Pause updates when tab is not visible
document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        if (isRealtimeEnabled) {
            stopRealtimeUpdates();
        }
    } else {
        if (window.location.pathname === '/dashboard' || window.location.pathname === '/traffic') {
            startRealtimeUpdates();
        }
    }
});

// Responsive Table Helper
function makeTablesResponsive() {
    const tables = document.querySelectorAll('table');
    tables.forEach(table => {
        if (!table.parentElement.classList.contains('table-responsive')) {
            const wrapper = document.createElement('div');
            wrapper.className = 'table-responsive';
            table.parentNode.insertBefore(wrapper, table);
            wrapper.appendChild(table);
        }
    });
}

// Initialize responsive tables on load
document.addEventListener('DOMContentLoaded', makeTablesResponsive);

// Notification System
class NotificationManager {
    static show(message, type = 'info', duration = 5000) {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; max-width: 300px;';
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after duration
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, duration);
    }
    
    static success(message) {
        this.show(message, 'success');
    }
    
    static error(message) {
        this.show(message, 'danger');
    }
    
    static warning(message) {
        this.show(message, 'warning');
    }
    
    static info(message) {
        this.show(message, 'info');
    }
}

// Make NotificationManager globally available
window.NotificationManager = NotificationManager;

// Connection Status Monitor
let connectionStatus = {
    isOnline: navigator.onLine,
    lastChecked: new Date()
};

function checkConnectionStatus() {
    fetch('/api/health', { method: 'HEAD' })
        .then(() => {
            if (!connectionStatus.isOnline) {
                connectionStatus.isOnline = true;
                NotificationManager.success('Connection restored');
            }
        })
        .catch(() => {
            if (connectionStatus.isOnline) {
                connectionStatus.isOnline = false;
                NotificationManager.error('Connection lost');
            }
        })
        .finally(() => {
            connectionStatus.lastChecked = new Date();
        });
}

// Check connection every 30 seconds
setInterval(checkConnectionStatus, 30000);

// Handle online/offline events
window.addEventListener('online', () => {
    connectionStatus.isOnline = true;
    NotificationManager.success('Back online');
});

window.addEventListener('offline', () => {
    connectionStatus.isOnline = false;
    NotificationManager.warning('You are offline');
});

console.log('WiFi Traffic Monitor JavaScript loaded successfully');
