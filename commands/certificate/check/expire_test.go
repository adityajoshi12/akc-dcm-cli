package check

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const validCertificate = `-----BEGIN CERTIFICATE-----
MIIBXzCCAQSgAwIBAgIGAZaQr6QlMAoGCCqGSM49BAMCMDYxNDAyBgNVBAMMK2VJ
ZURvOEZYOE92UWRtNHg0aldQY3BDcjA3RERGVGtWZ2g2U0tCMHh1Zm8wHhcNMjUw
NTAyMTEwOTEyWhcNMjYwMjI2MTEwOTEyWjA2MTQwMgYDVQQDDCtlSWVEbzhGWDhP
dlFkbTR4NGpXUGNwQ3IwN0RERlRrVmdoNlNLQjB4dWZvMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEUw60uDmeGTMx5o6THZsYMOYTyCAw06flKUfa43fHyt2uUM9W
MeR6OaA8394RFjs+TM17KVs5iXKZL3GjFymANjAKBggqhkjOPQQDAgNJADBGAiEA
4YfXGJPHFBhzqQdFkJuXfIM/Ylu3jKFg+MSFLc5VeSQCIQDA3YEWGvQ/hbRZk6TJ
sL3f4hqnxSu6abjv5Y9MBWA5Wg==
-----END CERTIFICATE-----`

func createTempCertFile(t *testing.T, content string) string {
	t.Helper()
	tempFile, err := os.CreateTemp("", "cert-*.crt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	if _, err := tempFile.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}

	tempFile.Close()
	return tempFile.Name()
}

func TestExpireCommand_Validate(t *testing.T) {
	cmd := ExpireCommand{}

	// Test with no arguments
	if err := cmd.Validate(); err == nil {
		t.Fatalf("expected error due to missing required fields, got nil")
	}

	// Test with CertPath
	cmd.CertPath = "dummy-cert-path"
	if err := cmd.Validate(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Test with FolderPath
	cmd.CertPath = ""
	cmd.FolderPath = "dummy-folder-path"
	if err := cmd.Validate(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestExpireCommand_Run(t *testing.T) {
	// Create a temporary certificate file with valid content
	validCert := createTempCertFile(t, validCertificate)
	defer os.Remove(validCert)

	cmd := ExpireCommand{
		CertPath: validCert,
	}

	if err := cmd.Run(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Test with a folder containing certificates
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "cert.crt")
	os.WriteFile(certFile, []byte(validCertificate), 0644)

	cmd = ExpireCommand{
		FolderPath: tempDir,
	}

	if err := cmd.Run(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestNewExpireCommand(t *testing.T) {
	// Create a temporary certificate file with valid content
	validCert := createTempCertFile(t, validCertificate)
	defer os.Remove(validCert)

	cmd := NewExpireCommand()

	if cmd.Use != "check" {
		t.Errorf("expected command use to be 'check', got %s", cmd.Use)
	}

	if cmd.Short != "Checking expiration date" {
		t.Errorf("expected command short description to be 'Checking expiration date', got %s", cmd.Short)
	}

	if cmd.Long != "Checking expiration date of certificate" {
		t.Errorf("expected command long description to be 'Checking expiration date of certificate', got %s", cmd.Long)
	}

	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"--cert-path=" + validCert})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
func TestCheckExpireDomain_ValidDomain(t *testing.T) {
	err := checkExpireDomain("google.com:443")
	if err != nil {
		t.Errorf("Expected no error for valid domain, got: %v", err)
	}
}

func TestCheckExpireDomain_InvalidDomain(t *testing.T) {
	err := checkExpireDomain("nonexistentdomainforsure12345.com:443")
	if err == nil {
		t.Errorf("Expected error for invalid domain, got nil")
	}
}

func TestCheckExpireDomain_DefaultPort(t *testing.T) {
	err := checkExpireDomain("google.com")
	if err != nil {
		t.Errorf("Expected no error for valid domain without port, got: %v", err)
	}
}
