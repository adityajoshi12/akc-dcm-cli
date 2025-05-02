package utilities_test

import (
	"crypto/ecdsa"

	"crypto/x509"
	"os"
	"testing"

	"github.com/adityajoshi12/akc-dcm-cli/utilities"
)

const validPrivateKey = `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCD+QX3B8sDl9GLkPZxY
LyQPmgDoaVQWSuD6kln53j9SLw==
-----END PRIVATE KEY-----
`

const validCertificate = `-----BEGIN CERTIFICATE-----
MIIBXzCCAQSgAwIBAgIGAZaQr6QlMAoGCCqGSM49BAMCMDYxNDAyBgNVBAMMK2VJ
ZURvOEZYOE92UWRtNHg0aldQY3BDcjA3RERGVGtWZ2g2U0tCMHh1Zm8wHhcNMjUw
NTAyMTEwOTEyWhcNMjYwMjI2MTEwOTEyWjA2MTQwMgYDVQQDDCtlSWVEbzhGWDhP
dlFkbTR4NGpXUGNwQ3IwN0RERlRrVmdoNlNLQjB4dWZvMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEUw60uDmeGTMx5o6THZsYMOYTyCAw06flKUfa43fHyt2uUM9W
MeR6OaA8394RFjs+TM17KVs5iXKZL3GjFymANjAKBggqhkjOPQQDAgNJADBGAiEA
4YfXGJPHFBhzqQdFkJuXfIM/Ylu3jKFg+MSFLc5VeSQCIQDA3YEWGvQ/hbRZk6TJ
sL3f4hqnxSu6abjv5Y9MBWA5Wg==
-----END CERTIFICATE-----
`

func createTempFile(t *testing.T, content string) string {
	t.Helper()
	tempFile, err := os.CreateTemp("", "temp-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	if _, err := tempFile.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}

	tempFile.Close()
	return tempFile.Name()
}

func TestParsePrivateKey(t *testing.T) {
	// Create a temporary private key file
	privateKeyPath := createTempFile(t, validPrivateKey)
	defer os.Remove(privateKeyPath)

	key, err := utilities.ParsePrivateKey(privateKeyPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	switch key.(type) {
	case *ecdsa.PrivateKey:
		// Valid ECDSA private key
	default:
		t.Fatalf("expected ECDSA private key, got %T", key)
	}
}

func TestParseCertificate(t *testing.T) {
	// Create a temporary certificate file
	certPath := createTempFile(t, validCertificate)
	defer os.Remove(certPath)

	cert, isJson, err := utilities.ParseCertificate(certPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if isJson {
		t.Errorf("expected isJson to be false, got true")
	}

	if cert == nil {
		t.Fatalf("expected certificate, got nil")
	}

	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("expected ECDSAWithSHA256, got %v", cert.SignatureAlgorithm)
	}
}
