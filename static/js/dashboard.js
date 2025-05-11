// Dashboard functionality
document.addEventListener('DOMContentLoaded', function() {
    // Initialize toast notification system
    function showToast(message) {
        const toast = document.createElement('div');
        toast.classList.add('toast');
        toast.textContent = message;
        
        const container = document.getElementById('toast-container');
        container.appendChild(toast);
        
        // Remove toast after animation completes
        setTimeout(() => {
            toast.remove();
        }, 3500);
    }
    
    // Make it available globally
    window.showToast = showToast;
    
    // Anti-fingerprinting and stealth measures
    // Mask canvas fingerprinting
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(type) {
        if (this.width === 16 && this.height === 16) {
            return originalToDataURL.apply(this, [type]);
        }
        const context = this.getContext('2d');
        const imageData = context.getImageData(0, 0, this.width, this.height);
        const pixels = imageData.data;
        
        // Add subtle noise to prevent fingerprinting
        for (let i = 0; i < pixels.length; i += 4) {
            pixels[i] = pixels[i] + Math.floor(Math.random() * 2);
            pixels[i+1] = pixels[i+1] + Math.floor(Math.random() * 2);
            pixels[i+2] = pixels[i+2] + Math.floor(Math.random() * 2);
        }
        
        context.putImageData(imageData, 0, 0);
        return originalToDataURL.apply(this, [type]);
    };
    
    // Initialize charts with empty data
    const cpuData = {
        labels: [],
        datasets: [{
            label: 'CPU Usage (%)',
            data: [],
            backgroundColor: 'rgba(0, 245, 139, 0.2)',
            borderColor: 'rgba(0, 245, 139, 1)',
            borderWidth: 2,
            tension: 0.4,
            fill: true,
            pointBackgroundColor: 'rgba(0, 245, 139, 1)',
            pointBorderColor: '#000',
            pointRadius: 3,
            pointHoverRadius: 5
        }]
    };
    
    const memoryData = {
        labels: [],
        datasets: [{
            label: 'Memory Usage (%)',
            data: [],
            backgroundColor: 'rgba(0, 226, 255, 0.2)',
            borderColor: 'rgba(0, 226, 255, 1)',
            borderWidth: 2,
            tension: 0.4,
            fill: true,
            pointBackgroundColor: 'rgba(0, 226, 255, 1)',
            pointBorderColor: '#000',
            pointRadius: 3,
            pointHoverRadius: 5
        }]
    };
    
    // Common chart options
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: {
                display: true,
                grid: {
                    color: 'rgba(255, 255, 255, 0.05)'
                },
                ticks: {
                    color: 'rgba(153, 163, 177, 0.8)',
                    font: {
                        family: "'Fira Code', monospace",
                        size: 10
                    },
                    maxRotation: 0,
                    autoSkip: true,
                    maxTicksLimit: 8
                }
            },
            y: {
                display: true,
                beginAtZero: true,
                max: 100,
                grid: {
                    color: 'rgba(255, 255, 255, 0.05)'
                },
                ticks: {
                    color: 'rgba(153, 163, 177, 0.8)',
                    font: {
                        family: "'Fira Code', monospace",
                        size: 10
                    },
                    callback: function(value) {
                        return value + '%';
                    }
                }
            }
        },
        plugins: {
            legend: {
                display: true,
                labels: {
                    color: '#ecf0f1',
                    font: {
                        family: "'Fira Code', monospace",
                        size: 11
                    },
                    boxWidth: 15,
                    padding: 15
                }
            },
            tooltip: {
                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                titleFont: {
                    family: "'Fira Code', monospace",
                    size: 12
                },
                bodyFont: {
                    family: "'Fira Code', monospace",
                    size: 11
                },
                borderColor: 'rgba(0, 245, 139, 0.3)',
                borderWidth: 1,
                displayColors: true,
                boxPadding: 5,
                callbacks: {
                    label: function(context) {
                        return context.dataset.label + ': ' + context.raw.toFixed(1) + '%';
                    }
                }
            }
        },
        animation: {
            duration: 800,
            easing: 'easeOutQuart'
        },
        interaction: {
            mode: 'index',
            intersect: false
        },
        elements: {
            line: {
                tension: 0.4
            },
            point: {
                radius: 3,
                hitRadius: 5,
                hoverRadius: 6
            }
        }
    };
    
    // Create charts with responsive options for each chart
    const cpuChartOptions = {
        ...chartOptions,
        maintainAspectRatio: false,
        aspectRatio: 2,
        layout: {
            padding: {
                left: 10,
                right: 10,
                top: 20,
                bottom: 10
            }
        },
        plugins: {
            ...chartOptions.plugins,
            title: {
                display: true,
                text: 'CPU Utilization',
                color: '#ecf0f1',
                font: {
                    family: "'Fira Code', monospace",
                    size: 14,
                    weight: 'bold'
                },
                padding: {
                    top: 10,
                    bottom: 20
                }
            }
        }
    };
    
    const memoryChartOptions = {
        ...chartOptions,
        maintainAspectRatio: false,
        aspectRatio: 2,
        layout: {
            padding: {
                left: 10,
                right: 10,
                top: 20,
                bottom: 10
            }
        },
        plugins: {
            ...chartOptions.plugins,
            title: {
                display: true,
                text: 'Memory Utilization',
                color: '#ecf0f1',
                font: {
                    family: "'Fira Code', monospace",
                    size: 14,
                    weight: 'bold'
                },
                padding: {
                    top: 10,
                    bottom: 20
                }
            }
        }
    };
    
    const cpuChart = new Chart(
        document.getElementById('cpu-chart').getContext('2d'),
        {
            type: 'line',
            data: cpuData,
            options: cpuChartOptions
        }
    );
    
    const memoryChart = new Chart(
        document.getElementById('memory-chart').getContext('2d'),
        {
            type: 'line',
            data: memoryData,
            options: memoryChartOptions
        }
    );
    
    // Handle resize events to ensure charts remain responsive
    window.addEventListener('resize', function() {
        cpuChart.resize();
        memoryChart.resize();
    });
    
    // Function to update charts with new data
    function updateCharts(cpuPercent, memoryPercent) {
        const now = new Date();
        const timeLabel = now.getHours() + ':' + 
                         (now.getMinutes() < 10 ? '0' : '') + now.getMinutes() + ':' + 
                         (now.getSeconds() < 10 ? '0' : '') + now.getSeconds();
        
        // Update CPU chart
        cpuData.labels.push(timeLabel);
        cpuData.datasets[0].data.push(cpuPercent);
        
        // Keep only the last 20 data points
        if (cpuData.labels.length > 20) {
            cpuData.labels.shift();
            cpuData.datasets[0].data.shift();
        }
        
        // Update Memory chart
        memoryData.labels.push(timeLabel);
        memoryData.datasets[0].data.push(memoryPercent);
        
        // Keep only the last 20 data points
        if (memoryData.labels.length > 20) {
            memoryData.labels.shift();
            memoryData.datasets[0].data.shift();
        }
        
        // Update the charts
        cpuChart.update();
        memoryChart.update();
    }
    
    // Function to update system information
    function updateSystemInfo(data) {
        // Update CPU info
        document.getElementById('cpu-info').innerHTML = `
            Model: ${data.cpu.model || 'Unknown'}<br>
            Cores: ${data.cpu.count || 'Unknown'}<br>
            Usage: ${data.cpu.percent ? data.cpu.percent[0].toFixed(1) + '%' : 'Unknown'}
        `;
        
        // Update Memory info
        document.getElementById('memory-info').innerHTML = `
            Total: ${formatBytes(data.memory.total)}<br>
            Used: ${formatBytes(data.memory.used)}<br>
            Usage: ${data.memory.percent ? data.memory.percent.toFixed(1) + '%' : 'Unknown'}
        `;
        
        // Update Disk info
        document.getElementById('disk-info').innerHTML = `
            Total: ${formatBytes(data.disk.total)}<br>
            Used: ${formatBytes(data.disk.used)}<br>
            Usage: ${data.disk.percent ? data.disk.percent.toFixed(1) + '%' : 'Unknown'}
        `;
        
        // Update Host info
        document.getElementById('host-info').innerHTML = `
            Hostname: ${data.host.hostname || 'Unknown'}<br>
            OS: ${data.host.platform || 'Unknown'}<br>
            Uptime: ${formatUptime(data.host.uptime)}
        `;
        
        // Update uptime display in footer
        document.getElementById('uptime').textContent = `Uptime: ${formatUptime(data.host.uptime)}`;
        
        // Update charts
        updateCharts(
            data.cpu.percent ? data.cpu.percent[0] : 0,
            data.memory.percent || 0
        );
    }
    
    // Function to update process list
    function updateProcesses(processes) {
        const processTable = document.getElementById('process-table');
        processTable.innerHTML = '';
        
        processes.forEach(process => {
            const row = document.createElement('tr');
            
            const pidCell = document.createElement('td');
            pidCell.textContent = process.pid;
            
            const nameCell = document.createElement('td');
            nameCell.textContent = process.name;
            
            const cpuCell = document.createElement('td');
            cpuCell.textContent = process.cpuPercent ? process.cpuPercent.toFixed(1) + '%' : '0%';
            
            const memCell = document.createElement('td');
            memCell.textContent = process.memPercent ? process.memPercent.toFixed(1) + '%' : '0%';
            
            row.appendChild(pidCell);
            row.appendChild(nameCell);
            row.appendChild(cpuCell);
            row.appendChild(memCell);
            
            processTable.appendChild(row);
        });
    }
    
    // Function to fetch system data from the server with retry mechanism
    function fetchSystemData() {
        fetch('/api/system')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                updateSystemInfo(data);
                showToast("System data updated");
            })
            .catch(error => {
                console.error('Error fetching system data:', error);
                
                // Retry after a delay (exponential backoff would be better in production)
                setTimeout(() => {
                    console.log('Retrying system data fetch...');
                    fetchSystemData();
                }, 5000);
            });
    }
    
    // Function to fetch process data from the server with retry mechanism
    function fetchProcessData() {
        fetch('/api/processes')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                updateProcesses(data);
            })
            .catch(error => {
                console.error('Error fetching process data:', error);
                
                // Retry after a delay
                setTimeout(() => {
                    console.log('Retrying process data fetch...');
                    fetchProcessData();
                }, 8000);
            });
    }
    
    // Function to fetch activity logs with retry mechanism
    function fetchActivityLogs() {
        fetch('/api/logs')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                const logContainer = document.getElementById('activity-log');
                const logList = document.createElement('ul');
                logList.className = 'log-list';
                
                data.forEach(log => {
                    const logItem = document.createElement('li');
                    logItem.className = 'log-item';
                    
                    // Add timestamp prefix if not already present
                    if (!log.includes('[')) {
                        const now = new Date();
                        const timestamp = `[${now.toLocaleTimeString()}] `;
                        logItem.innerHTML = `<span class="log-time">${timestamp}</span><span class="log-content">${log}</span>`;
                    } else {
                        // Extract timestamp and content if present
                        const parts = log.match(/^\[(.*?)\]\s(.*)/);
                        if (parts && parts.length > 2) {
                            logItem.innerHTML = `<span class="log-time">[${parts[1]}]</span><span class="log-content">${parts[2]}</span>`;
                        } else {
                            logItem.textContent = log;
                        }
                    }
                    
                    logList.appendChild(logItem);
                });
                
                logContainer.innerHTML = '';
                logContainer.appendChild(logList);
                
                // Auto-scroll to bottom
                logContainer.scrollTop = logContainer.scrollHeight;
            })
            .catch(error => {
                console.error('Error fetching logs:', error);
                
                // Retry after a delay
                setTimeout(() => {
                    console.log('Retrying logs fetch...');
                    fetchActivityLogs();
                }, 10000);
            });
    }
    
    // Helper function to format bytes
    function formatBytes(bytes, decimals = 2) {
        if (!bytes) return '0 Bytes';
        
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
        
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
    
    // Helper function to format uptime
    function formatUptime(seconds) {
        if (!seconds) return 'Unknown';
        
        const days = Math.floor(seconds / (3600 * 24));
        const hours = Math.floor((seconds % (3600 * 24)) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        
        let result = '';
        if (days > 0) result += days + 'd ';
        if (hours > 0 || days > 0) result += hours + 'h ';
        result += minutes + 'm';
        
        return result;
    }
    
    // Initial data fetch
    fetchSystemData();
    fetchProcessData();
    fetchActivityLogs();
    
    // Set up periodic updates
    setInterval(fetchSystemData, 5000);   // Every 5 seconds
    setInterval(fetchProcessData, 10000); // Every 10 seconds
    setInterval(fetchActivityLogs, 15000); // Every 15 seconds
});
