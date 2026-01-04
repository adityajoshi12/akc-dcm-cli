package utilities_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/adityajoshi12/akc-dcm-cli/utilities"
	"strings"
	"testing"
)

const testCertificate = `-----BEGIN CERTIFICATE-----
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

func TestCertificateText(t *testing.T) {
	block, _ := pem.Decode([]byte(testCertificate))
	if block == nil {
		t.Fatalf("failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse test certificate: %v", err)
	}

	output, err := utilities.CertificateText(cert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if output == "" {
		t.Errorf("expected non-empty output, got empty string")
	}
}

func TestCertificateTextWithExtensions(t *testing.T) {
	block, _ := pem.Decode([]byte(testCertificate))
	if block == nil {
		t.Fatalf("failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse test certificate: %v", err)
	}

	cert.Extensions = []pkix.Extension{
		{
			Id:       []int{2, 5, 29, 14},
			Critical: false,
			Value:    []byte{0x04, 0x03, 0x02, 0x01, 0x01}, // Correctly encoded ASN.1 value for Subject Key Identifier
		},
	}

	output, err := utilities.CertificateText(cert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !strings.Contains(output, "X509v3 Subject Key Identifier") {
		t.Errorf("expected output to contain 'X509v3 Subject Key Identifier', got %s", output)
	}
}

func TestCertificateRequestTextWithExtensions(t *testing.T) {
	csr := &x509.CertificateRequest{
		Version: 3,
		Subject: pkix.Name{
			CommonName:   "Test CN",
			Organization: []string{"Test Org"},
		},
		PublicKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     elliptic.P256().Params().Gx,
			Y:     elliptic.P256().Params().Gy,
		},
		PublicKeyAlgorithm: x509.ECDSA, // Explicitly set the public key algorithm to ECDSA
		Extensions: []pkix.Extension{
			{
				Id:       []int{2, 5, 29, 17},
				Critical: false,
				Value:    []byte{0x01, 0x02, 0x03},
			},
		},
	}

	output, err := utilities.CertificateRequestText(csr)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !strings.Contains(output, "X509v3 Subject Alternative Name") {
		t.Errorf("expected output to contain 'X509v3 Subject Alternative Name', got %s", output)
	}
}
