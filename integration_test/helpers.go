package integration_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adityajoshi12/akc-dcm-cli/commands"
	"github.com/spf13/cobra"
)

// IntegrationTestConfig holds paths to test certificates and directories
type IntegrationTestConfig struct {
	TestDataDir     string
	TempOutputDir   string
	CACertPath      string
	CAKeyPath       string
	ICACertPath     string
	ICAKeyPath      string
	ValidCertPath   string
	ValidKeyPath    string
	ExpiredCertPath string
}

// TestResult captures the result of a command execution
type TestResult struct {
	Command      string
	Args         []string
	ExitCode     int
	StdOut       string
	StdErr       string
	Duration     time.Duration
	FilesCreated []string
}

// CertificateInfo holds certificate metadata for validation
type CertificateInfo struct {
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber string
	DNSNames     []string
}

// setupTestEnvironment initializes test directories and generates test certificates
func setupTestEnvironment() (*IntegrationTestConfig, error) {
	// Create test data directory structure
	testDataDir := "integration_test/testdata"
	dirs := []string{
		filepath.Join(testDataDir, "ca"),
		filepath.Join(testDataDir, "intermediate"),
		filepath.Join(testDataDir, "end-entity"),
		filepath.Join(testDataDir, "invalid"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	// Create temporary output directory
	tempOutputDir := "integration_test/temp_output"
	if err := os.MkdirAll(tempOutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp output directory: %v", err)
	}

	config := &IntegrationTestConfig{
		TestDataDir:     testDataDir,
		TempOutputDir:   tempOutputDir,
		CACertPath:      filepath.Join(testDataDir, "ca", "ca-cert.pem"),
		CAKeyPath:       filepath.Join(testDataDir, "ca", "ca-key.pem"),
		ICACertPath:     filepath.Join(testDataDir, "intermediate", "ica-cert.pem"),
		ICAKeyPath:      filepath.Join(testDataDir, "intermediate", "ica-key.pem"),
		ValidCertPath:   filepath.Join(testDataDir, "end-entity", "valid-cert.pem"),
		ValidKeyPath:    filepath.Join(testDataDir, "end-entity", "valid-key.pem"),
		ExpiredCertPath: filepath.Join(testDataDir, "end-entity", "expired-cert.pem"),
	}

	// Generate test certificates
	if err := generateTestCertificates(config); err != nil {
		return nil, fmt.Errorf("failed to generate test certificates: %v", err)
	}

	return config, nil
}

// cleanupTestEnvironment removes temporary files and directories with enhanced resource management
func cleanupTestEnvironment(config *IntegrationTestConfig) error {
	if config == nil {
		return nil
	}

	var errors []string

	// Remove temporary output directory
	if err := os.RemoveAll(config.TempOutputDir); err != nil {
		errors = append(errors, fmt.Sprintf("failed to cleanup temp output directory: %v", err))
	}

	// Clean up any remaining temporary files in the system temp directory
	// that might have been created during testing
	tempPattern := filepath.Join(os.TempDir(), "dcm-integration-test-*")
	matches, err := filepath.Glob(tempPattern)
	if err == nil {
		for _, match := range matches {
			if err := os.RemoveAll(match); err != nil {
				errors = append(errors, fmt.Sprintf("failed to cleanup temp file %s: %v", match, err))
			}
		}
	}

	// Report any cleanup errors
	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// generateTestCertificates creates all test certificate fixtures
func generateTestCertificates(config *IntegrationTestConfig) error {
	// Generate CA certificate and key
	caKey, caCert, err := generateCACertificate()
	if err != nil {
		return fmt.Errorf("failed to generate CA certificate: %v", err)
	}

	// Save CA certificate and key
	if err := saveCertificate(config.CACertPath, caCert); err != nil {
		return err
	}
	if err := savePrivateKey(config.CAKeyPath, caKey); err != nil {
		return err
	}

	// Generate Intermediate CA certificate and key
	icaKey, icaCert, err := generateIntermediateCACertificate(caCert, caKey)
	if err != nil {
		return fmt.Errorf("failed to generate intermediate CA certificate: %v", err)
	}

	// Save ICA certificate and key
	if err := saveCertificate(config.ICACertPath, icaCert); err != nil {
		return err
	}
	if err := savePrivateKey(config.ICAKeyPath, icaKey); err != nil {
		return err
	}

	// Generate valid end-entity certificate
	validKey, validCert, err := generateEndEntityCertificate(icaCert, icaKey, time.Now().AddDate(1, 0, 0))
	if err != nil {
		return fmt.Errorf("failed to generate valid end-entity certificate: %v", err)
	}

	// Save valid certificate and key
	if err := saveCertificate(config.ValidCertPath, validCert); err != nil {
		return err
	}
	if err := savePrivateKey(config.ValidKeyPath, validKey); err != nil {
		return err
	}

	// Generate expired certificate
	_, expiredCert, err := generateEndEntityCertificate(icaCert, icaKey, time.Now().AddDate(-1, 0, 0))
	if err != nil {
		return fmt.Errorf("failed to generate expired certificate: %v", err)
	}

	// Save expired certificate
	if err := saveCertificate(config.ExpiredCertPath, expiredCert); err != nil {
		return err
	}

	// Generate soon-to-expire certificate
	soonExpirePath := filepath.Join(config.TestDataDir, "end-entity", "soon-expire-cert.pem")
	_, soonExpireCert, err := generateEndEntityCertificate(icaCert, icaKey, time.Now().AddDate(0, 0, 7))
	if err != nil {
		return fmt.Errorf("failed to generate soon-to-expire certificate: %v", err)
	}

	if err := saveCertificate(soonExpirePath, soonExpireCert); err != nil {
		return err
	}

	// Generate malformed certificate for error testing
	malformedPath := filepath.Join(config.TestDataDir, "invalid", "malformed-cert.pem")
	malformedContent := "-----BEGIN CERTIFICATE-----\nINVALID_CERTIFICATE_DATA\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(malformedPath, []byte(malformedContent), 0644); err != nil {
		return fmt.Errorf("failed to create malformed certificate: %v", err)
	}

	// Generate wrong private key for mismatch testing
	wrongKeyPath := filepath.Join(config.TestDataDir, "invalid", "wrong-key.pem")
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate wrong key: %v", err)
	}
	if err := savePrivateKey(wrongKeyPath, wrongKey); err != nil {
		return err
	}

	return nil
}

// generateCACertificate creates a self-signed CA certificate
func generateCACertificate() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

// generateIntermediateCACertificate creates an intermediate CA certificate
func generateIntermediateCACertificate(caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{"Test Intermediate CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

// generateEndEntityCertificate creates an end-entity certificate with specified expiry
func generateEndEntityCertificate(issuerCert *x509.Certificate, issuerKey *ecdsa.PrivateKey, notAfter time.Time) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization:  []string{"Test End Entity"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "test.example.com",
		},
		NotBefore:   time.Now(),
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"test.example.com", "www.test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &key.PublicKey, issuerKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

// saveCertificate saves a certificate to a PEM file
func saveCertificate(path string, cert *x509.Certificate) error {
	certOut := &bytes.Buffer{}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return err
	}
	return os.WriteFile(path, certOut.Bytes(), 0644)
}

// savePrivateKey saves a private key to a PEM file
func savePrivateKey(path string, key *ecdsa.PrivateKey) error {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	keyOut := &bytes.Buffer{}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return err
	}
	return os.WriteFile(path, keyOut.Bytes(), 0600)
}

// executeCommand executes a DCM CLI command programmatically and captures output
func executeCommand(args []string) (*TestResult, error) {
	startTime := time.Now()

	// Create root command
	rootCmd := &cobra.Command{
		Use:   "dcm",
		Short: "The command line interface for digital certificate management (dcm)",
	}
	rootCmd.AddCommand(commands.All()...)

	// Capture stdout and stderr
	var stdout, stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs(args)

	// Execute command
	err := rootCmd.Execute()
	duration := time.Since(startTime)

	result := &TestResult{
		Command:  "dcm",
		Args:     args,
		StdOut:   stdout.String(),
		StdErr:   stderr.String(),
		Duration: duration,
	}

	if err != nil {
		result.ExitCode = 1
	} else {
		result.ExitCode = 0
	}

	return result, err
}

// assertCommandSuccess validates that a command executed successfully
func assertCommandSuccess(t *testing.T, result *TestResult) {
	t.Helper()
	if result.ExitCode != 0 {
		t.Errorf("Command failed with exit code %d\nStdOut: %s\nStdErr: %s",
			result.ExitCode, result.StdOut, result.StdErr)
	}
}

// assertCommandFailure validates that a command failed as expected
func assertCommandFailure(t *testing.T, result *TestResult) {
	t.Helper()
	if result.ExitCode == 0 {
		t.Errorf("Expected command to fail, but it succeeded\nStdOut: %s", result.StdOut)
	}
}

// assertFileExists validates that a file exists at the specified path
func assertFileExists(t *testing.T, filepath string) {
	t.Helper()
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		t.Errorf("Expected file does not exist: %s", filepath)
	}
}

// assertFileNotExists validates that a file does not exist at the specified path
func assertFileNotExists(t *testing.T, filepath string) {
	t.Helper()
	if _, err := os.Stat(filepath); err == nil {
		t.Errorf("Expected file to not exist, but it does: %s", filepath)
	}
}

// assertOutputContains validates that command output contains expected text
func assertOutputContains(t *testing.T, result *TestResult, expected string) {
	t.Helper()
	if !strings.Contains(result.StdOut, expected) {
		t.Errorf("Expected output to contain '%s', but got:\n%s", expected, result.StdOut)
	}
}

// assertOutputNotContains validates that command output does not contain specified text
func assertOutputNotContains(t *testing.T, result *TestResult, unexpected string) {
	t.Helper()
	if strings.Contains(result.StdOut, unexpected) {
		t.Errorf("Expected output to not contain '%s', but got:\n%s", unexpected, result.StdOut)
	}
}

// validateCertificateOutput parses and validates certificate inspection output
func validateCertificateOutput(t *testing.T, output string, expectedInfo *CertificateInfo) {
	t.Helper()

	// Basic validation that output contains certificate information
	if expectedInfo.Subject != "" && !strings.Contains(output, expectedInfo.Subject) {
		t.Errorf("Expected output to contain subject '%s', but got:\n%s", expectedInfo.Subject, output)
	}

	if expectedInfo.Issuer != "" && !strings.Contains(output, expectedInfo.Issuer) {
		t.Errorf("Expected output to contain issuer '%s', but got:\n%s", expectedInfo.Issuer, output)
	}

	if expectedInfo.SerialNumber != "" && !strings.Contains(output, expectedInfo.SerialNumber) {
		t.Errorf("Expected output to contain serial number '%s', but got:\n%s", expectedInfo.SerialNumber, output)
	}
}

// parseCertificateFile reads and parses a certificate file for validation
func parseCertificateFile(t *testing.T, certPath string) *x509.Certificate {
	t.Helper()

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read certificate file %s: %v", certPath, err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatalf("Failed to decode PEM block from certificate file %s", certPath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate from file %s: %v", certPath, err)
	}

	return cert
}

// validateRenewedCertificate validates that a renewed certificate meets expectations
func validateRenewedCertificate(t *testing.T, originalCertPath, renewedCertPath string, expectedDays int) {
	t.Helper()

	originalCert := parseCertificateFile(t, originalCertPath)
	renewedCert := parseCertificateFile(t, renewedCertPath)

	// Validate that subject information is preserved
	if originalCert.Subject.String() != renewedCert.Subject.String() {
		t.Errorf("Subject mismatch: original=%s, renewed=%s",
			originalCert.Subject.String(), renewedCert.Subject.String())
	}

	// Validate that the new expiry is approximately the expected number of days from now
	expectedExpiry := time.Now().AddDate(0, 0, expectedDays)
	timeDiff := renewedCert.NotAfter.Sub(expectedExpiry).Abs()
	if timeDiff > 24*time.Hour {
		t.Errorf("Renewed certificate expiry (%v) is not within 24 hours of expected (%v)",
			renewedCert.NotAfter, expectedExpiry)
	}

	// Validate that the renewed certificate has a valid date range
	if renewedCert.NotBefore.After(renewedCert.NotAfter) {
		t.Errorf("Renewed certificate has invalid date range: NotBefore (%v) is after NotAfter (%v)",
			renewedCert.NotBefore, renewedCert.NotAfter)
	}
}

// createTempOutputPath creates a unique temporary output file path with enhanced isolation
func createTempOutputPath(config *IntegrationTestConfig, filename string) string {
	// Create a unique subdirectory for this test to ensure isolation
	testID := fmt.Sprintf("%d_%d", time.Now().UnixNano(), os.Getpid())
	testDir := filepath.Join(config.TempOutputDir, testID)

	// Ensure the directory exists
	if err := os.MkdirAll(testDir, 0755); err != nil {
		// Fallback to the original behavior if directory creation fails
		return filepath.Join(config.TempOutputDir, fmt.Sprintf("%s_%s", testID, filename))
	}

	return filepath.Join(testDir, filename)
}

// createIsolatedTestDir creates an isolated directory for a specific test
func createIsolatedTestDir(config *IntegrationTestConfig, testName string) (string, func(), error) {
	testID := fmt.Sprintf("%s_%d_%d", testName, time.Now().UnixNano(), os.Getpid())
	testDir := filepath.Join(config.TempOutputDir, testID)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create isolated test directory: %v", err)
	}

	// Return cleanup function
	cleanup := func() {
		if err := os.RemoveAll(testDir); err != nil {
			fmt.Printf("Warning: failed to cleanup test directory %s: %v\n", testDir, err)
		}
	}

	return testDir, cleanup, nil
}

// validateTestPerformance checks if a test operation completed within acceptable time limits
func validateTestPerformance(t *testing.T, operation string, duration time.Duration, maxDuration time.Duration) {
	t.Helper()
	if duration > maxDuration {
		t.Errorf("%s took too long: %v (should be under %v)", operation, duration, maxDuration)
	}
}

// ensureTestIsolation verifies that tests don't interfere with each other
func ensureTestIsolation(t *testing.T, config *IntegrationTestConfig) {
	t.Helper()

	// Check that temp directory is clean at the start of each test
	entries, err := os.ReadDir(config.TempOutputDir)
	if err != nil {
		t.Fatalf("Failed to read temp directory: %v", err)
	}

	// Count non-directory entries (files left from previous tests)
	fileCount := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			fileCount++
		}
	}

	if fileCount > 0 {
		t.Errorf("Test isolation violation: found %d files in temp directory from previous tests", fileCount)
	}
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// parsePrivateKeyFile reads and parses a private key file for testing
func parsePrivateKeyFile(t *testing.T, keyPath string) *ecdsa.PrivateKey {
	t.Helper()

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read private key file %s: %v", keyPath, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		t.Fatalf("Failed to decode PEM block from private key file %s", keyPath)
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key from file %s: %v", keyPath, err)
	}

	return key
}

// createRSACertificate generates an RSA certificate for testing different key types
func createRSACertificate(t *testing.T, config *IntegrationTestConfig) (string, string) {
	t.Helper()

	// Generate RSA private key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization:  []string{"Test RSA Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "rsa-test.example.com",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"rsa-test.example.com", "www.rsa-test.example.com"},
	}

	// Sign with intermediate CA
	icaCert := parseCertificateFile(t, config.ICACertPath)
	icaKey := parsePrivateKeyFile(t, config.ICAKeyPath)

	certDER, err := x509.CreateCertificate(rand.Reader, template, icaCert, &rsaKey.PublicKey, icaKey)
	if err != nil {
		t.Fatalf("Failed to create RSA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse RSA certificate: %v", err)
	}

	// Save certificate and key
	certPath := createTempOutputPath(config, "rsa-cert.pem")
	keyPath := createTempOutputPath(config, "rsa-key.pem")

	if err := saveCertificate(certPath, cert); err != nil {
		t.Fatalf("Failed to save RSA certificate: %v", err)
	}

	if err := saveRSAPrivateKey(keyPath, rsaKey); err != nil {
		t.Fatalf("Failed to save RSA private key: %v", err)
	}

	return certPath, keyPath
}

// createCertificateWithExtensions generates a certificate with various extensions for testing
func createCertificateWithExtensions(t *testing.T, config *IntegrationTestConfig) string {
	t.Helper()

	// Generate ECDSA private key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Create certificate template with extensive extensions
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization:       []string{"Test Extensions Org"},
			OrganizationalUnit: []string{"Test OU"},
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"San Francisco"},
			StreetAddress:      []string{"123 Test St"},
			PostalCode:         []string{"12345"},
			CommonName:         "ext-test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature |
			x509.KeyUsageContentCommitment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageEmailProtection,
		},
		DNSNames: []string{
			"ext-test.example.com",
			"www.ext-test.example.com",
			"api.ext-test.example.com",
			"*.ext-test.example.com",
		},
		EmailAddresses:        []string{"test@example.com", "admin@ext-test.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.100"), net.ParseIP("10.0.0.1")},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign with intermediate CA
	icaCert := parseCertificateFile(t, config.ICACertPath)
	icaKey := parsePrivateKeyFile(t, config.ICAKeyPath)

	certDER, err := x509.CreateCertificate(rand.Reader, template, icaCert, &key.PublicKey, icaKey)
	if err != nil {
		t.Fatalf("Failed to create certificate with extensions: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate with extensions: %v", err)
	}

	// Save certificate
	certPath := createTempOutputPath(config, "ext-cert.pem")
	if err := saveCertificate(certPath, cert); err != nil {
		t.Fatalf("Failed to save certificate with extensions: %v", err)
	}

	return certPath
}

// saveRSAPrivateKey saves an RSA private key to a PEM file
func saveRSAPrivateKey(path string, key *rsa.PrivateKey) error {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)

	keyOut := &bytes.Buffer{}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return err
	}
	return os.WriteFile(path, keyOut.Bytes(), 0600)
}
