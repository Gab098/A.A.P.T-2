// App principale
class AAPTApp {
    constructor() {
        this.results = [];
        this.isScanning = false;
        this.updateInterval = null;
        this.init();
    }

    init() {
        this.bindEvents();
        this.startStatusUpdates();
        this.loadResults();
    }

    bindEvents() {
        // Scan button
        const scanBtn = document.getElementById('scan-btn');
        scanBtn.addEventListener('click', () => this.startScan());

        // Quick target buttons
        const quickTargetBtns = document.querySelectorAll('.quick-target-btn');
        quickTargetBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const target = btn.dataset.target;
                document.getElementById('target-input').value = target;
                this.startScan();
            });
        });

        // Enter key on input
        const targetInput = document.getElementById('target-input');
        targetInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.startScan();
            }
        });
    }

    async startScan() {
        const targetInput = document.getElementById('target-input');
        const target = targetInput.value.trim();

        if (!target) {
            this.showNotification('Please enter a target', 'error');
            return;
        }

        if (this.isScanning) {
            this.showNotification('Scan already in progress', 'error');
            return;
        }

        this.isScanning = true;
        this.showLoading(true);
        this.updateScanButton(true);

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ target })
            });

            const data = await response.json();

            if (data.success) {
                this.showNotification(data.message, 'success');
                targetInput.value = '';
            } else {
                this.showNotification(data.error, 'error');
            }
        } catch (error) {
            this.showNotification('Network error', 'error');
            console.error('Scan error:', error);
        } finally {
            this.isScanning = false;
            this.showLoading(false);
            this.updateScanButton(false);
        }
    }

    updateScanButton(disabled) {
        const scanBtn = document.getElementById('scan-btn');
        const buttonText = scanBtn.querySelector('.button-text');
        
        if (disabled) {
            scanBtn.disabled = true;
            buttonText.textContent = 'Scanning...';
        } else {
            scanBtn.disabled = false;
            buttonText.textContent = 'Start Scan';
        }
    }

    showLoading(show) {
        const overlay = document.getElementById('loading-overlay');
        if (show) {
            overlay.classList.remove('hidden');
        } else {
            overlay.classList.add('hidden');
        }
    }

    showNotification(message, type = 'success') {
        const notification = document.getElementById('notification');
        const notificationText = document.getElementById('notification-text');
        
        notification.className = `notification ${type}`;
        notificationText.textContent = message;
        
        notification.classList.remove('hidden');
        notification.classList.add('show');
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                notification.classList.add('hidden');
            }, 300);
        }, 3000);
    }

    async loadResults() {
        try {
            const response = await fetch('/api/results');
            const results = await response.json();
            this.results = results;
            this.renderResults();
        } catch (error) {
            console.error('Error loading results:', error);
        }
    }

    renderResults() {
        const resultsList = document.getElementById('results-list');
        
        if (this.results.length === 0) {
            resultsList.innerHTML = `
                <div class="no-results">
                    <div class="no-results-icon">🔍</div>
                    <p>No scans yet. Start a scan to see results here.</p>
                </div>
            `;
            return;
        }

        resultsList.innerHTML = this.results.map(result => this.createResultHTML(result)).join('');
    }

    createResultHTML(result) {
        const timestamp = new Date(result.timestamp).toLocaleString();
        let resultType = 'nmap';
        let content = '';

        if (result.open_ports) {
            // Nmap result
            const ports = result.open_ports.map(port => 
                `${port.port}/${port.protocol} (${port.service})`
            ).join(', ');
            content = `Found ${result.open_ports.length} open ports: ${ports}`;
        } else if (result.vulnerabilities_found !== undefined) {
            // Nuclei result
            resultType = 'nuclei';
            content = `Found ${result.vulnerabilities_found} vulnerabilities: ${result.vulnerabilities.join(', ')}`;
        } else {
            content = JSON.stringify(result, null, 2);
        }

        return `
            <div class="result-item">
                <div class="result-header">
                    <span class="result-target">${result.target}</span>
                    <span class="result-timestamp">${timestamp}</span>
                </div>
                <div class="result-type ${resultType}">${resultType.toUpperCase()}</div>
                <div class="result-content">${content}</div>
            </div>
        `;
    }

    async updateStatus() {
        try {
            const response = await fetch('/api/status');
            const status = await response.json();
            
            // Update status indicators
            const statusDot = document.getElementById('status-dot');
            const statusText = document.getElementById('status-text');
            const rabbitmqStatus = document.getElementById('rabbitmq-status');
            const resultsCount = document.getElementById('results-count');
            const lastUpdate = document.getElementById('last-update');

            // RabbitMQ status
            if (status.rabbitmq === 'online') {
                statusDot.classList.add('online');
                statusText.textContent = 'Online';
                rabbitmqStatus.textContent = 'Online';
                rabbitmqStatus.style.color = '#00ff41';
            } else {
                statusDot.classList.remove('online');
                statusText.textContent = 'Offline';
                rabbitmqStatus.textContent = 'Offline';
                rabbitmqStatus.style.color = '#ff4444';
            }

            // Results count
            resultsCount.textContent = status.results_count;

            // Last update
            if (status.timestamp) {
                const lastUpdateTime = new Date(status.timestamp).toLocaleTimeString();
                lastUpdate.textContent = lastUpdateTime;
            }

        } catch (error) {
            console.error('Error updating status:', error);
        }
    }

    startStatusUpdates() {
        // Update status every 5 seconds
        this.updateStatus();
        this.updateInterval = setInterval(() => {
            this.updateStatus();
            this.loadResults(); // Also refresh results
        }, 5000);
    }

    stopStatusUpdates() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
    }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.aaptApp = new AAPTApp();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.aaptApp) {
        window.aaptApp.stopStatusUpdates();
    }
}); 