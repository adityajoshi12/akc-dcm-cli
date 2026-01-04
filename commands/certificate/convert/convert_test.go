package convert

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewConvertCertificateCommand(t *testing.T) {
	cmd := NewConvertCertificateCommand()

	if cmd.Use != "convert" {
		t.Errorf("Expected Use to be 'convert', got %s", cmd.Use)
	}

	if cmd.Short != "Convert certificate formats" {
		t.Errorf("Expected Short description, got %s", cmd.Short)
	}
}

func TestValidation(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()
	testPEM := filepath.Join(tmpDir, "test.pem")
	testKey := filepath.Join(tmpDir, "test.key")
	testP12 := filepath.Join(tmpDir, "test.p12")

	// Create dummy files
	_ = os.WriteFile(testPEM, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"), 0644)
	_ = os.WriteFile(testKey, []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"), 0644)
	_ = os.WriteFile(testP12, []byte("dummy p12 data"), 0644)

	tests := []struct {
		name        string
		cmd         ConvertCommand
		expectError bool
		errorMsg    string
	}{
		{
			name: "missing source file",
			cmd: ConvertCommand{
				from: "",
			},
			expectError: true,
			errorMsg:    "source file (--from) is required",
		},
		{
			name: "non-existent source file",
			cmd: ConvertCommand{
				from: "/nonexistent/file.pem",
			},
			expectError: true,
		},
		{
			name: "missing destination format for PEM",
			cmd: ConvertCommand{
				from:       testPEM,
				fromFormat: "pem",
				toFormat:   "",
			},
			expectError: true,
		},
		{
			name: "PEM to P12 missing key",
			cmd: ConvertCommand{
				from:       testPEM,
				fromFormat: "pem",
				toFormat:   "p12",
				to:         filepath.Join(tmpDir, "out.p12"),
			},
			expectError: true,
			errorMsg:    "private key file (--key) is required for PEM to PKCS#12 conversion",
		},
		{
			name: "PEM to P12 missing password",
			cmd: ConvertCommand{
				from:       testPEM,
				fromFormat: "pem",
				toFormat:   "p12",
				to:         filepath.Join(tmpDir, "out.p12"),
				key:        testKey,
			},
			expectError: true,
			errorMsg:    "password (--password) is required for PKCS#12 conversion",
		},
		{
			name: "P12 missing password",
			cmd: ConvertCommand{
				from:       testP12,
				fromFormat: "p12",
				toFormat:   "pem",
			},
			expectError: true,
			errorMsg:    "password (--password) is required to read PKCS#12 file",
		},
		{
			name: "P12 to PEM missing output files",
			cmd: ConvertCommand{
				from:       testP12,
				fromFormat: "p12",
				toFormat:   "pem",
				password:   "test123",
			},
			expectError: true,
			errorMsg:    "specify either --to (for combined output) or --cert-out and --key-out (for separate files)",
		},
		{
			name: "same format conversion",
			cmd: ConvertCommand{
				from:       testPEM,
				fromFormat: "pem",
				toFormat:   "pem",
			},
			expectError: true,
			errorMsg:    "source and destination formats are the same (pem)",
		},
		{
			name: "invalid source format",
			cmd: ConvertCommand{
				from:       testPEM,
				fromFormat: "invalid",
				toFormat:   "pem",
			},
			expectError: true,
			errorMsg:    "invalid source format. Supported: pem, der, p12",
		},
		{
			name: "invalid destination format",
			cmd: ConvertCommand{
				from:       testPEM,
				fromFormat: "pem",
				toFormat:   "invalid",
			},
			expectError: true,
			errorMsg:    "invalid destination format. Supported: pem, der, p12",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.expectError && tt.errorMsg != "" && err != nil {
				if err.Error() != tt.errorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			}
		})
	}
}

func TestNormalizeFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"pem", "pem"},
		{"der", "der"},
		{"p12", "p12"},
		{"pkcs12", "p12"},
		{"pfx", "p12"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeFormat(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeFormat(%s) = %s, expected %s", tt.input, result, tt.expected)
			}
		})
	}
}
