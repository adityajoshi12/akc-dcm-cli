package renew_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/adityajoshi12/akc-dcm-cli/commands/certificate/renew"
)

func createTempFile(t *testing.T, name, content string) string {
	t.Helper()
	tempFile, err := os.CreateTemp("", name)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	if _, err := tempFile.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}

	tempFile.Close()
	return tempFile.Name()
}

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

func TestNewReNewCertificateCommand(t *testing.T) {
	// Create temporary files for the test
	parentCert := createTempFile(t, "parent-cert.pem", validCertificate)
	parentKey := createTempFile(t, "parent-key.pem", validPrivateKey)
	oldCert := createTempFile(t, "old-cert.pem", validCertificate)
	oldKey := createTempFile(t, "old-key.pem", validPrivateKey)
	defer os.Remove(parentCert)
	defer os.Remove(parentKey)
	defer os.Remove(oldCert)
	defer os.Remove(oldKey)
	defer os.Remove("new-cert.pem")

	cmd := renew.NewReNewCertificateCommand()

	// Test with no arguments
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error due to missing required flags, got nil")
	}

	// Test with required arguments
	cmd.SetArgs([]string{
		"--parent-cert=" + parentCert,
		"--parent-private-key=" + parentKey,
		"--old-cert=" + oldCert,
		"--old-private-key=" + oldKey,
		"--days=30",
		"--output=new-cert.pem",
	})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if output.String() == "" {
		t.Fatalf("expected output, got empty string")
	}
}

func TestReNewCommand_Validate(t *testing.T) {
	c := renew.ReNewCommand{
		ParenCertPath:      "",
		ParentPrivKeyPath:  "",
		OldCertPath:        "",
		PrivKeyOldCertPath: "",
		Day:                0,
	}

	err := c.Validate()
	if err == nil {
		t.Fatalf("expected error due to missing required fields, got nil")
	}

	c.ParenCertPath = "parent-cert.pem"
	c.ParentPrivKeyPath = "parent-key.pem"
	c.OldCertPath = "old-cert.pem"
	c.PrivKeyOldCertPath = "old-key.pem"
	c.Day = 30

	err = c.Validate()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
