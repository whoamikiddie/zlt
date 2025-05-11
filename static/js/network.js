// Network information handling
document.addEventListener('DOMContentLoaded', function() {
    // Get DOM elements
    const interfacesTable = document.getElementById('interfaces-table');
    const connectionsTable = document.getElementById('connections-table');
    const refreshConnectionsButton = document.getElementById('refresh-connections');
    const networkStats = document.getElementById('network-stats');
    
    // Load network interfaces information with enhanced security features
    function loadNetworkInterfaces() {
        interfacesTable.innerHTML = '<tr><td colspan="3"><div class="loading-spinner"></div> Loading interfaces...</td></tr>';
        connectionsTable.innerHTML = '<tr><td colspan="5"><div class="loading-spinner"></div> Loading connections...</td></tr>';
        
        // Add security panel if it doesn't exist yet
        if (!document.getElementById('security-panel')) {
            const securityPanel = document.createElement('div');
            securityPanel.id = 'security-panel';
            securityPanel.className = 'panel security-panel';
            
            const header = document.createElement('h2');
            header.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-shield"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                Security Status
            `;
            
            const content = document.createElement('div');
            content.id = 'security-content';
            content.innerHTML = '<div class="loading-spinner"></div> Scanning system security...';
            
            securityPanel.appendChild(header);
            securityPanel.appendChild(content);
            
            // Add after connections panel
            document.querySelector('.network').appendChild(securityPanel);
        }
        
        fetch('/api/network')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                // Update interfaces table
                interfacesTable.innerHTML = '';
                
                if (!data.interfaces || data.interfaces.length === 0) {
                    interfacesTable.innerHTML = '<tr><td colspan="3">No network interfaces found</td></tr>';
                    return;
                }
                
                data.interfaces.forEach(iface => {
                    const row = document.createElement('tr');
                    
                    // Name column
                    const nameCell = document.createElement('td');
                    nameCell.textContent = iface.name;
                    
                    // MAC address column
                    const macCell = document.createElement('td');
                    macCell.textContent = iface.hardwareAddr || 'N/A';
                    
                    // IP addresses column
                    const ipCell = document.createElement('td');
                    if (iface.addresses && iface.addresses.length > 0) {
                        ipCell.textContent = iface.addresses.join(', ');
                    } else {
                        ipCell.textContent = 'No IP addresses';
                    }
                    
                    // Append cells to row
                    row.appendChild(nameCell);
                    row.appendChild(macCell);
                    row.appendChild(ipCell);
                    
                    // Append row to table
                    interfacesTable.appendChild(row);
                });
                
                // Update network stats
                networkStats.textContent = `Interfaces: ${data.interfaces.length}`;
                
                // Update connections table
                connectionsTable.innerHTML = '';
                
                if (!data.connections || data.connections.length === 0) {
                    connectionsTable.innerHTML = '<tr><td colspan="5">No active connections</td></tr>';
                } else {
                    data.connections.forEach(conn => {
                        const row = document.createElement('tr');
                        
                        // Create cells
                        const localCell = document.createElement('td');
                        localCell.textContent = conn.localAddr || 'N/A';
                        
                        const remoteCell = document.createElement('td');
                        remoteCell.textContent = conn.remoteAddr || 'N/A';
                        
                        const statusCell = document.createElement('td');
                        statusCell.textContent = conn.status || 'N/A';
                        if (conn.status === 'ESTABLISHED') {
                            statusCell.classList.add('connection-established');
                        } else if (conn.status === 'LISTEN') {
                            statusCell.classList.add('connection-listen');
                        }
                        
                        const pidCell = document.createElement('td');
                        pidCell.textContent = conn.pid || 'N/A';
                        
                        const processCell = document.createElement('td');
                        processCell.textContent = conn.process || 'N/A';
                        
                        // Append cells to row
                        row.appendChild(localCell);
                        row.appendChild(remoteCell);
                        row.appendChild(statusCell);
                        row.appendChild(pidCell);
                        row.appendChild(processCell);
                        
                        // Append row to table
                        connectionsTable.appendChild(row);
                    });
                }
                
                // Update security status section if available
                if (data.security) {
                    const securityContent = document.getElementById('security-content');
                    const lastScanDate = new Date(data.security.lastScan).toLocaleString();
                    
                    securityContent.innerHTML = `
                        <div class="security-status ${data.security.status.toLowerCase() === 'secure' ? 'secure' : 'warning'}">
                            <div class="status-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-check-circle"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                            </div>
                            <div class="status-details">
                                <h3>${data.security.status}</h3>
                                <p>Last scan: ${lastScanDate}</p>
                                <p>Firewall: ${data.security.firewall_status}</p>
                                <p>Encryption: ${data.security.encryption}</p>
                                <p>Threats detected: ${data.security.threats_detected}</p>
                            </div>
                        </div>
                    `;
                }
                
                // Sort connections by status (LISTEN first, then others)
                data.connections.sort((a, b) => {
                    if (a.status === 'LISTEN' && b.status !== 'LISTEN') return -1;
                    if (a.status !== 'LISTEN' && b.status === 'LISTEN') return 1;
                    return 0;
                });
                
                data.connections.forEach(conn => {
                    const row = document.createElement('tr');
                    
                    // Local address column
                    const localCell = document.createElement('td');
                    localCell.textContent = conn.localAddr;
                    
                    // Remote address column
                    const remoteCell = document.createElement('td');
                    remoteCell.textContent = conn.remoteAddr || '*';
                    
                    // Status column
                    const statusCell = document.createElement('td');
                    statusCell.textContent = conn.status;
                    
                    // Protocol type column
                    const typeCell = document.createElement('td');
                    typeCell.textContent = conn.type || 'Unknown';
                    
                    // PID column
                    const pidCell = document.createElement('td');
                    pidCell.textContent = conn.pid || 'N/A';
                    
                    // Append cells to row
                    row.appendChild(localCell);
                    row.appendChild(remoteCell);
                    row.appendChild(statusCell);
                    row.appendChild(typeCell);
                    row.appendChild(pidCell);
                    
                    // Add class for listening ports
                    if (conn.status === 'LISTEN') {
                        row.classList.add('listening');
                    }
                    
                    // Append row to table
                    connectionsTable.appendChild(row);
                });
                
                // Update network stats with connection count
                networkStats.textContent += ` | Connections: ${data.connections.length}`;
            })
            .catch(error => {
                console.error('Error loading network information:', error);
                interfacesTable.innerHTML = `<tr><td colspan="3">Error loading interfaces: ${error.message}</td></tr>`;
                connectionsTable.innerHTML = `<tr><td colspan="5">Error loading connections: ${error.message}</td></tr>`;
            });
    }
    
    // Set up refresh button event listener
    refreshConnectionsButton.addEventListener('click', () => {
        loadNetworkInterfaces();
    });
    
    // Display tunnel status and details
    function displayTunnelInfo() {
        // The tunnel information is already rendered server-side in the template
        // We can add additional dynamic information here if needed in the future
    }
    
    // Initial load
    loadNetworkInterfaces();
    displayTunnelInfo();
    
    // Set up periodic refresh
    setInterval(loadNetworkInterfaces, 30000); // Refresh every 30 seconds
});
