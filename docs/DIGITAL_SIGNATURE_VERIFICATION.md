# SecureMonitor™ Enterprise Edition - Digital Signature Verification Guide

## Introduction

SecureMonitor™ Enterprise Edition uses industry-standard digital signatures to ensure the authenticity and integrity of its software components. This guide provides instructions for verifying the digital signatures of SecureMonitor™ components to ensure they have not been tampered with and are genuine releases from SecureTech Solutions Ltd.

## Why Verify Digital Signatures?

Digital signatures provide several important security benefits:

1. **Authenticity**: Confirms the software was created by SecureTech Solutions Ltd.
2. **Integrity**: Verifies the software has not been modified since it was signed
3. **Non-repudiation**: Provides proof of the software's origin
4. **Malware Protection**: Helps protect against modified or counterfeit versions

## Components and Signature Types

SecureMonitor™ Enterprise Edition uses different signature types for different components:

| Component Type | Signature Type | Verification Method |
|----------------|----------------|---------------------|
| Windows Executables (.exe, .dll) | Authenticode | Windows Explorer, sigcheck, PowerShell |
| macOS Applications (.app) | Apple Developer ID | Gatekeeper, codesign |
| Linux Packages (.deb, .rpm) | GPG | apt-key, rpm --checksig |
| Scripts (.ps1, .sh) | GPG | gpg --verify |
| Configuration Files | GPG | gpg --verify |

## Verification Methods

### Windows Components

#### Using Windows Explorer

1. Right-click on the executable file (e.g., SecureMonitor-Enterprise-Setup.exe)
2. Select "Properties"
3. Click on the "Digital Signatures" tab
4. Select the signature from "SecureTech Solutions Ltd."
5. Click "Details"
6. Click "View Certificate"
7. Verify the certificate was issued to "SecureTech Solutions Ltd."
8. Verify the certificate is valid and issued by a trusted authority

#### Using PowerShell

```powershell
# Verify executable signature
Get-AuthenticodeSignature -FilePath "C:\path\to\SecureMonitor-Enterprise-Setup.exe"

# Check certificate details
(Get-AuthenticodeSignature -FilePath "C:\path\to\SecureMonitor-Enterprise-Setup.exe").SignerCertificate | Format-List
```

The output should show:
- Status: Valid
- SignatureType: Authenticode
- Subject: CN=SecureTech Solutions Ltd., O=SecureTech Solutions Ltd., L=San Francisco, S=California, C=US

#### Using Sigcheck (Sysinternals)

```
sigcheck -a -h C:\path\to\SecureMonitor-Enterprise-Setup.exe
```

Look for:
- Verified: Signed
- Signing date: [Check date is reasonable]
- Publisher: SecureTech Solutions Ltd.
- Description: SecureMonitor Enterprise Edition

### macOS Components

#### Using Finder

1. Right-click on the .pkg file or application
2. Select "Get Info"
3. Expand the "Digital Signatures" section
4. Verify it shows "SecureTech Solutions Ltd." as the signer

#### Using Terminal

```bash
# For .pkg files
pkgutil --check-signature /path/to/SecureMonitor-Enterprise.pkg

# For applications
codesign -v -d --verbose=4 /Applications/SecureMonitor\ Enterprise.app
```

Look for:
- Authority=Developer ID Application: SecureTech Solutions Ltd.
- Authority=Developer ID Certification Authority
- Authority=Apple Root CA

### Linux Components

#### Debian/Ubuntu Packages

```bash
# Import our GPG key if you haven't already
wget -qO - https://keys.securemonitor-enterprise.example.com/enterprise.asc | sudo apt-key add -

# Verify a downloaded .deb package
dpkg-sig --verify securemonitor-enterprise_2.1.5.deb
```

The output should show: `GOODSIG _SECUREMONITOR SecureTech Solutions Ltd. <security@securemonitor-enterprise.example.com>`

#### RPM Packages

```bash
# Import our GPG key if you haven't already
rpm --import https://keys.securemonitor-enterprise.example.com/enterprise.asc

# Verify an RPM package
rpm --checksig securemonitor-enterprise-2.1.5.rpm
```

The output should show: `securemonitor-enterprise-2.1.5.rpm: digests signatures OK`

#### Script and Configuration Files

All script and configuration files are signed with a detached GPG signature (.asc file):

```bash
# Import our GPG key if you haven't already
gpg --keyserver keys.gnupg.net --recv-keys 0x9AECF18D4BA68072

# Verify a script
gpg --verify script.sh.asc script.sh
```

The output should show: `Good signature from "SecureTech Solutions Ltd. <security@securemonitor-enterprise.example.com>"`

## Certificate Details

Our software is signed using certificates with the following details:

### Windows Certificates

- Subject: CN=SecureTech Solutions Ltd., O=SecureTech Solutions Ltd., L=San Francisco, S=California, C=US
- Issuer: CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, O=DigiCert, Inc., C=US
- Valid From: January 15, 2023
- Valid To: January 15, 2026
- Serial Number: 0d:e7:a8:c5:f9:e7:b4:a8:d8:42:9b:3f:c3:2a:b8:d4
- Thumbprint: 83:A9:D1:4F:B2:CF:E9:33:BA:F3:0E:27:8A:44:5B:7C:AB:12:F4:E7

### macOS Certificates

- Developer ID: Developer ID Application: SecureTech Solutions Ltd. (AB12CD345E)
- Team ID: AB12CD345E
- Authority: Apple Developer ID Certification Authority

### GPG Key

- Key ID: 0x9AECF18D4BA68072
- Fingerprint: F842 97C0 7E6A A729 11D4 96EB 9AEC F18D 4BA6 8072
- User ID: SecureTech Solutions Ltd. <security@securemonitor-enterprise.example.com>

## Certificate Chain Verification

For advanced verification, you can validate the entire certificate chain:

### Windows Certificate Chain

```powershell
# Extract the certificate
$cert = (Get-AuthenticodeSignature "C:\path\to\SecureMonitor-Enterprise-Setup.exe").SignerCertificate

# Build and validate the chain
$chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
$chain.Build($cert)

# Display the chain
$chain.ChainElements | ForEach-Object {
    $_.Certificate | Format-List Subject, Issuer, Thumbprint, NotBefore, NotAfter
}
```

### Online Certificate Status Protocol (OCSP)

You can verify if the certificate has been revoked using OCSP:

```powershell
# Check OCSP status
$chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
$chain.Build($cert)

# Check for revocation issues
$chain.ChainStatus | Where-Object { $_.Status -ne 'NoError' }
```

If no output is displayed, the certificate is valid and not revoked.

## Verifying File Hashes

In addition to digital signatures, you can verify file integrity using cryptographic hashes:

```powershell
# Windows PowerShell
Get-FileHash -Algorithm SHA256 -Path "C:\path\to\SecureMonitor-Enterprise-Setup.exe"
```

```bash
# macOS/Linux
shasum -a 256 /path/to/SecureMonitor-Enterprise.pkg
```

Compare the output with the hashes published on our secure download page: https://downloads.securemonitor-enterprise.example.com/verify

## Enterprise Verification Automation

For automated verification in enterprise environments, we provide scripts and configuration for common deployment tools:

### SCCM Detection Method

```powershell
# SCCM PowerShell detection script
$filePath = "C:\Program Files\SecureTech Solutions Ltd\SecureMonitor Enterprise Edition\SecureMonitor.exe"
$expectedThumbprint = "83A9D14FB2CFE933BAF30E278A445B7CAB12F4E7"

if (Test-Path $filePath) {
    $actualThumbprint = (Get-AuthenticodeSignature $filePath).SignerCertificate.Thumbprint
    if ($actualThumbprint -eq $expectedThumbprint) {
        Write-Output "Signature valid"
        exit 0
    } else {
        Write-Output "Signature invalid"
        exit 1
    }
} else {
    Write-Output "File not found"
    exit 1
}
```

### Group Policy Software Restriction Policy

For Windows environments using Software Restriction Policies:

1. Open Group Policy Management Console
2. Create or edit a GPO
3. Navigate to Computer Configuration > Windows Settings > Security Settings > Software Restriction Policies
4. Create a new Software Restriction Policy
5. Add a new Additional Rule of type "Certificate Rule"
6. Browse to any SecureMonitor™ executable and select the certificate
7. Choose "Allow" as the security level

## Troubleshooting

### Common Verification Issues

#### "Certificate not trusted" error

Ensure your system's root certificate store is up to date:

- Windows: Run Windows Update to get the latest root certificates
- macOS: Ensure you're on a supported macOS version with updated certificates
- Linux: Update your ca-certificates package (`sudo apt update && sudo apt install ca-certificates`)

#### "Signature invalid" error

This may indicate tampering or corruption:

1. Download a fresh copy from our official site
2. Verify your download was complete
3. Contact our security team if issues persist

#### "Certificate revoked" error

If you receive a revocation error:

1. Ensure your system can access the internet
2. Check that OCSP/CRL servers are accessible
3. Download the latest version from our official site

## Security Incident Reporting

If you encounter verification issues that suggest tampering or counterfeiting, please report it immediately:

- Email: security@securemonitor-enterprise.example.com
- Security Hotline: +1-555-SECURE-2

Please include:
- The file name and version
- Where you obtained the file
- The exact error message or verification failure
- Screenshots of any error messages

## Conclusion

Verifying digital signatures is a crucial step in ensuring the security and integrity of your SecureMonitor™ Enterprise Edition deployment. By following the procedures in this guide, you can confirm that your software is genuine and has not been tampered with.

For any questions about digital signature verification, please contact our security team at security@securemonitor-enterprise.example.com.

---

© 2023-2025 SecureTech Solutions Ltd. All rights reserved.