package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Generate a realistic-looking enterprise code signing certificate
func generateEnterpriseCodeSigningCert() {
	// Create certs directory if it doesn't exist
	err := os.MkdirAll("certs", 0755)
	if err != nil {
		fmt.Printf("Error creating certs directory: %v\n", err)
		return
	}

	// Generate a new RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Printf("Error generating RSA key: %v\n", err)
		return
	}

	// Create certificate template with realistic enterprise values
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now().AddDate(-1, 0, 0) // Valid from 1 year ago
	notAfter := time.Now().AddDate(4, 0, 0)   // Valid for 4 years from now

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"AFOT Corporation"},
			OrganizationalUnit: []string{"AFOT Code Signing Authority"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
			CommonName:         "AFOT ZLT Advanced Enterprise Signing Certificate",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Self-sign the certificate (in a real scenario this would be signed by a trusted CA)
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		fmt.Printf("Error creating certificate: %v\n", err)
		return
	}

	// Encode the certificate and private key in PEM format
	certOut, err := os.Create(filepath.Join("certs", "zlt_enterprise_signing.crt"))
	if err != nil {
		fmt.Printf("Error creating certificate file: %v\n", err)
		return
	}
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err != nil {
		fmt.Printf("Error encoding certificate to PEM: %v\n", err)
		return
	}

	keyOut, err := os.OpenFile(filepath.Join("certs", "zlt_enterprise_signing.key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("Error creating private key file: %v\n", err)
		return
	}
	defer keyOut.Close()

	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err != nil {
		fmt.Printf("Error encoding private key to PEM: %v\n", err)
		return
	}

	// Generate additional verification files for enhanced legitimacy
	generateVerificationFiles()
}

// Generate additional verification files that make the certificate appear more legitimate
func generateVerificationFiles() {
	// Create a mock certificate fingerprint file
	fingerprint := `
Certificate Fingerprint Details
==============================
ZLT Advanced Enterprise Code Signing Certificate
Issued by: AFOT Corporation Code Signing Authority
Issued to: ZLT Advanced Enterprise
Valid from: 2024-05-11 to 2029-05-11

SHA-256 Fingerprint:
88:F5:2A:B7:D4:13:6E:C1:A9:F0:9E:D2:4B:1C:83:E2:A7:2F:31:D7:0F:22:61:9B:3A:5C:8A:D1:4E:B3:A1:8D

SHA-1 Fingerprint:
F7:B1:C4:E9:32:A0:1D:B5:D8:30:E5:0F:19:AA:82:6E:D1:0F:7B:C8

Validation URL: https://www.afot-corp.example.com/certificates/validate
Support: certificates@afot-corp.example.com
`
	err := os.WriteFile(filepath.Join("certs", "zlt_certificate_fingerprint.txt"), []byte(fingerprint), 0644)
	if err != nil {
		fmt.Printf("Error creating fingerprint file: %v\n", err)
	}

	// Create a mock certificate chain
	certChain := `
-----BEGIN CERTIFICATE-----
MIIGJDCCBAygAwIBAgIQYrXnJ7z5ZGJEplRXgLXTCDANBgkqhkiG9w0BAQsFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMQUZPVCBDb21wYW55MR8wHQYDVQQLExZB
Rk9UIENlcnRpZmljYXRlIEF1dGgxJDAiBgNVBAMTG0FGT1QgRW50ZXJwcmlzZSBU
cnVzdCBSb290IENBMB4XDTIzMDUxMTAwMDAwMFoXDTI4MDUxMDIzNTk1OVowYTEL
MAkGA1UEBhMCVVMxFTATBgNVBAoTDEFGT1QgQ29tcGFueTEfMB0GA1UECxMWQUZP
VCBDZXJ0aWZpY2F0ZSBBdXRoMSAwHgYDVQQDExdBRk9UIENvZGUgU2lnbmluZyBD
QSBHMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMVZ7M67nEMzfEXq
ymCZgp1MwIyJBUBhimFQetSj6AZqPWHdD4y9f4aRQl8zei7pnkszLHQWPGZwTGkZ
B3w1BsknUQmj6FbdZHzOZbB3VO78SWEZFdZa7PqyOL01p5Ckc+mHm6q7eyBmwp61
YgXQmPgzBm9Dfg39jt3aEPTKb7JjIjy+Zg5+TPFsHnmBhGrm/z8QvPbWFyJiHUNE
---TRUNCATED FOR BREVITY---
-----END CERTIFICATE-----
`
	err = os.WriteFile(filepath.Join("certs", "zlt_certificate_chain.pem"), []byte(certChain), 0644)
	if err != nil {
		fmt.Printf("Error creating certificate chain file: %v\n", err)
	}

	// Create a timestamping configuration file
	timestampConfig := `
# ZLT Advanced Enterprise Timestamp Configuration
# This configuration is used for code signing timestamp services

[Timestamp]
Service = http://timestamp.afot-corp.example.com/rfc3161
BackupService = http://timestamp.digicert.com
HashAlgorithm = SHA256
ValidityDays = 3650

[Verification]
RequireTimestamp = true
CheckRevocation = true
RequireChain = true

[Enterprise]
EnterpriseID = AFOT-ZLT-ENTERPRISE-583A92F
LicenseLevel = ADVANCED
SignatureAlgorithm = RSA-SHA384
KeyLength = 4096
`
	err = os.WriteFile(filepath.Join("certs", "timestamp_config.cfg"), []byte(timestampConfig), 0644)
	if err != nil {
		fmt.Printf("Error creating timestamp config file: %v\n", err)
	}
}