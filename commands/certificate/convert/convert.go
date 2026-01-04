package convert

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/adityajoshi12/akc-dcm-cli/commands/common"
	"github.com/adityajoshi12/akc-dcm-cli/utilities"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

func NewConvertCertificateCommand() *cobra.Command {

	c := ConvertCommand{}

	command := &cobra.Command{
		Short: "Convert certificate formats",
		Long:  "Convert certificates between different formats (PEM, DER, PKCS#12)",
		Use:   "convert",
		RunE: func(_ *cobra.Command, _ []string) error {
			return c.Run()
		},
		Args: c.ParseArgs(),

		PreRunE: func(_ *cobra.Command, _ []string) error {
			if err := c.Validate(); err != nil {
				return err
			}

			return nil
		},
	}

	flags := command.Flags()
	flags.StringVar(&c.from, "from", "", "Source certificate file path")
	flags.StringVar(&c.to, "to", "", "Destination file path")
	flags.StringVar(&c.fromFormat, "from-format", "", "Source format: pem, der, p12 (auto-detect if not specified)")
	flags.StringVar(&c.toFormat, "to-format", "", "Destination format: pem, der, p12")
	flags.StringVar(&c.key, "key", "", "Private key file (required for PEM to PKCS#12)")
	flags.StringVar(&c.password, "password", "", "Password for PKCS#12 files")
	flags.StringVar(&c.certOut, "cert-out", "", "Output certificate file (when extracting from PKCS#12)")
	flags.StringVar(&c.keyOut, "key-out", "", "Output key file (when extracting from PKCS#12)")

	// Add file path completion
	_ = command.MarkFlagFilename("from", "pem", "crt", "cer", "der", "p12", "pfx")
	_ = command.MarkFlagFilename("key", "pem", "key")
	_ = command.MarkFlagFilename("to")
	_ = command.MarkFlagFilename("cert-out")
	_ = command.MarkFlagFilename("key-out")

	return command

}

type ConvertCommand struct {
	common.Command
	from       string
	to         string
	fromFormat string
	toFormat   string
	key        string
	password   string
	certOut    string
	keyOut     string
}

func (c *ConvertCommand) Run() error {
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Printf("%s Detected source format: %s\n", green("✓"), c.fromFormat)
	fmt.Printf("%s Converting %s → %s\n", yellow("→"), c.fromFormat, c.toFormat)

	var err error
	switch c.fromFormat {
	case "pem":
		err = c.convertFromPEM()
	case "der":
		err = c.convertFromDER()
	case "p12":
		err = c.convertFromP12()
	default:
		return fmt.Errorf("unsupported source format: %s", c.fromFormat)
	}

	if err != nil {
		return err
	}

	fmt.Printf("%s Certificate converted successfully\n", green("✓"))
	return nil
}

func (c *ConvertCommand) convertFromPEM() error {
	switch c.toFormat {
	case "der":
		return c.pemToDER()
	case "p12":
		return c.pemToP12()
	}
	return fmt.Errorf("unsupported conversion: pem → %s", c.toFormat)
}

func (c *ConvertCommand) convertFromDER() error {
	switch c.toFormat {
	case "pem":
		return c.derToPEM()
	case "p12":
		return c.derToP12()
	}
	return fmt.Errorf("unsupported conversion: der → %s", c.toFormat)
}

func (c *ConvertCommand) convertFromP12() error {
	switch c.toFormat {
	case "pem":
		return c.p12ToPEM()
	case "der":
		return c.p12ToDER()
	}
	return fmt.Errorf("unsupported conversion: p12 → %s", c.toFormat)
}

// PEM to DER conversion
func (c *ConvertCommand) pemToDER() error {
	pemData, err := os.ReadFile(c.from)
	if err != nil {
		return fmt.Errorf("failed to read PEM file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	err = os.WriteFile(c.to, block.Bytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write DER file: %w", err)
	}

	fileInfo, _ := os.Stat(c.to)
	fmt.Printf("  Output: %s (%d bytes)\n", c.to, fileInfo.Size())
	return nil
}

// DER to PEM conversion
func (c *ConvertCommand) derToPEM() error {
	derData, err := os.ReadFile(c.from)
	if err != nil {
		return fmt.Errorf("failed to read DER file: %w", err)
	}

	// Try to parse as certificate first
	cert, err := x509.ParseCertificate(derData)
	blockType := "CERTIFICATE"

	if err != nil {
		// Try as private key
		_, err = x509.ParsePKCS8PrivateKey(derData)
		if err == nil {
			blockType = "PRIVATE KEY"
		} else {
			// Try PKCS1 private key
			_, err = x509.ParsePKCS1PrivateKey(derData)
			if err == nil {
				blockType = "RSA PRIVATE KEY"
			} else {
				return errors.New("failed to parse DER data as certificate or private key")
			}
		}
	} else {
		// Successfully parsed as certificate
		_ = cert
	}

	pemBlock := &pem.Block{
		Type:  blockType,
		Bytes: derData,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	err = os.WriteFile(c.to, pemData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write PEM file: %w", err)
	}

	fileInfo, _ := os.Stat(c.to)
	fmt.Printf("  Output: %s (%d bytes)\n", c.to, fileInfo.Size())
	fmt.Printf("  Type: %s\n", blockType)
	return nil
}

// PEM to PKCS#12 conversion
func (c *ConvertCommand) pemToP12() error {
	cert, _, err := utilities.ParseCertificate(c.from)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	key, err := utilities.ParsePrivateKey(c.key)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	pfxData, err := pkcs12.Encode(rand.Reader, key, cert, nil, c.password)
	if err != nil {
		return fmt.Errorf("failed to encode PKCS#12: %w", err)
	}

	err = os.WriteFile(c.to, pfxData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write PKCS#12 file: %w", err)
	}

	fileInfo, _ := os.Stat(c.to)
	fmt.Printf("  Output: %s (%d bytes)\n", c.to, fileInfo.Size())
	fmt.Printf("  Certificate: %s\n", cert.Subject.CommonName)
	return nil
}

// DER to PKCS#12 conversion
func (c *ConvertCommand) derToP12() error {
	derData, err := os.ReadFile(c.from)
	if err != nil {
		return fmt.Errorf("failed to read DER file: %w", err)
	}

	cert, err := x509.ParseCertificate(derData)
	if err != nil {
		return fmt.Errorf("failed to parse DER certificate: %w", err)
	}

	key, err := utilities.ParsePrivateKey(c.key)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	pfxData, err := pkcs12.Encode(rand.Reader, key, cert, nil, c.password)
	if err != nil {
		return fmt.Errorf("failed to encode PKCS#12: %w", err)
	}

	err = os.WriteFile(c.to, pfxData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write PKCS#12 file: %w", err)
	}

	fileInfo, _ := os.Stat(c.to)
	fmt.Printf("  Output: %s (%d bytes)\n", c.to, fileInfo.Size())
	fmt.Printf("  Certificate: %s\n", cert.Subject.CommonName)
	return nil
}

// PKCS#12 to PEM conversion
func (c *ConvertCommand) p12ToPEM() error {
	pfxData, err := os.ReadFile(c.from)
	if err != nil {
		return fmt.Errorf("failed to read PKCS#12 file: %w", err)
	}

	key, cert, err := pkcs12.Decode(pfxData, c.password)
	if err != nil {
		return fmt.Errorf("failed to decode PKCS#12 (check password): %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Encode key to PEM
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Write to separate files or combined
	if c.certOut != "" && c.keyOut != "" {
		// Write separate files
		err = os.WriteFile(c.certOut, certPEM, 0644)
		if err != nil {
			return fmt.Errorf("failed to write certificate file: %w", err)
		}

		err = os.WriteFile(c.keyOut, keyPEM, 0600)
		if err != nil {
			return fmt.Errorf("failed to write key file: %w", err)
		}

		certInfo, _ := os.Stat(c.certOut)
		keyInfo, _ := os.Stat(c.keyOut)
		fmt.Printf("  Certificate: %s (%d bytes)\n", c.certOut, certInfo.Size())
		fmt.Printf("  Private Key: %s (%d bytes)\n", c.keyOut, keyInfo.Size())
	} else {
		// Write combined file
		combined := append(certPEM, keyPEM...)
		err = os.WriteFile(c.to, combined, 0600)
		if err != nil {
			return fmt.Errorf("failed to write combined PEM file: %w", err)
		}

		fileInfo, _ := os.Stat(c.to)
		fmt.Printf("  Output: %s (%d bytes)\n", c.to, fileInfo.Size())
		fmt.Printf("  Contains: Certificate + Private Key\n")
	}

	fmt.Printf("  Subject: %s\n", cert.Subject.CommonName)
	return nil
}

// PKCS#12 to DER conversion (extracts certificate only)
func (c *ConvertCommand) p12ToDER() error {
	pfxData, err := os.ReadFile(c.from)
	if err != nil {
		return fmt.Errorf("failed to read PKCS#12 file: %w", err)
	}

	_, cert, err := pkcs12.Decode(pfxData, c.password)
	if err != nil {
		return fmt.Errorf("failed to decode PKCS#12 (check password): %w", err)
	}

	output := c.to
	if output == "" {
		output = c.certOut
	}

	err = os.WriteFile(output, cert.Raw, 0644)
	if err != nil {
		return fmt.Errorf("failed to write DER file: %w", err)
	}

	fileInfo, _ := os.Stat(output)
	fmt.Printf("  Output: %s (%d bytes)\n", output, fileInfo.Size())
	fmt.Printf("  Certificate: %s\n", cert.Subject.CommonName)
	fmt.Printf("  Note: Private key not extracted (DER format for certificate only)\n")
	return nil
}

func (c *ConvertCommand) Validate() error {
	// Require source file
	if c.from == "" {
		return errors.New("source file (--from) is required")
	}

	// Check if source file exists
	if _, err := os.Stat(c.from); os.IsNotExist(err) {
		return errors.New("source file does not exist: " + c.from)
	}

	// Auto-detect source format if not specified
	if c.fromFormat == "" {
		detected, err := detectFormat(c.from)
		if err != nil {
			return errors.New("could not auto-detect source format, please specify --from-format")
		}
		c.fromFormat = detected
	}

	// Normalize format names
	c.fromFormat = normalizeFormat(c.fromFormat)
	if c.toFormat != "" {
		c.toFormat = normalizeFormat(c.toFormat)
	}

	// Validate format values
	validFormats := map[string]bool{"pem": true, "der": true, "p12": true, "pkcs12": true}
	if !validFormats[c.fromFormat] {
		return errors.New("invalid source format. Supported: pem, der, p12")
	}
	if c.toFormat != "" && !validFormats[c.toFormat] {
		return errors.New("invalid destination format. Supported: pem, der, p12")
	}

	// Validate based on conversion type
	switch c.fromFormat {
	case "pem":
		return c.validateFromPEM()
	case "der":
		return c.validateFromDER()
	case "p12", "pkcs12":
		return c.validateFromP12()
	}

	return nil
}

func (c *ConvertCommand) validateFromPEM() error {
	if c.toFormat == "" {
		return errors.New("destination format (--to-format) is required")
	}

	switch c.toFormat {
	case "der":
		// PEM to DER: needs output file
		if c.to == "" {
			return errors.New("destination file (--to) is required for PEM to DER conversion")
		}

	case "p12", "pkcs12":
		// PEM to P12: needs private key, output file, and password
		if c.key == "" {
			return errors.New("private key file (--key) is required for PEM to PKCS#12 conversion")
		}
		if _, err := os.Stat(c.key); os.IsNotExist(err) {
			return errors.New("private key file does not exist: " + c.key)
		}
		if c.to == "" {
			return errors.New("destination file (--to) is required for PEM to PKCS#12 conversion")
		}
		if c.password == "" {
			return errors.New("password (--password) is required for PKCS#12 conversion")
		}

	case "pem":
		return errors.New("source and destination formats are the same (pem)")
	}

	return nil
}

func (c *ConvertCommand) validateFromDER() error {
	if c.toFormat == "" {
		return errors.New("destination format (--to-format) is required")
	}

	switch c.toFormat {
	case "pem":
		// DER to PEM: needs output file
		if c.to == "" {
			return errors.New("destination file (--to) is required for DER to PEM conversion")
		}

	case "p12", "pkcs12":
		// DER to P12: needs private key, output file, and password
		if c.key == "" {
			return errors.New("private key file (--key) is required for DER to PKCS#12 conversion")
		}
		if _, err := os.Stat(c.key); os.IsNotExist(err) {
			return errors.New("private key file does not exist: " + c.key)
		}
		if c.to == "" {
			return errors.New("destination file (--to) is required for DER to PKCS#12 conversion")
		}
		if c.password == "" {
			return errors.New("password (--password) is required for PKCS#12 conversion")
		}

	case "der":
		return errors.New("source and destination formats are the same (der)")
	}

	return nil
}

func (c *ConvertCommand) validateFromP12() error {
	// P12 to other formats: needs password
	if c.password == "" {
		return errors.New("password (--password) is required to read PKCS#12 file")
	}

	if c.toFormat == "" {
		return errors.New("destination format (--to-format) is required")
	}

	switch c.toFormat {
	case "pem":
		// P12 to PEM: needs cert-out and key-out OR single output file
		if c.certOut == "" && c.keyOut == "" && c.to == "" {
			return errors.New("specify either --to (for combined output) or --cert-out and --key-out (for separate files)")
		}
		// If using separate outputs, both must be specified
		if (c.certOut != "" || c.keyOut != "") && (c.certOut == "" || c.keyOut == "") {
			return errors.New("both --cert-out and --key-out must be specified for separate file extraction")
		}

	case "der":
		// P12 to DER: needs output file
		if c.to == "" && c.certOut == "" {
			return errors.New("destination file (--to or --cert-out) is required for PKCS#12 to DER conversion")
		}

	case "p12", "pkcs12":
		return errors.New("source and destination formats are the same (p12)")
	}

	return nil
}

// detectFormat tries to detect the file format based on content
func detectFormat(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	// Check for PEM format (starts with -----BEGIN)
	if bytes.Contains(data, []byte("-----BEGIN")) {
		return "pem", nil
	}

	// Check for PKCS#12 signature (starts with 0x30 0x82 or 0x30 0x80 for ASN.1 SEQUENCE)
	// PKCS#12 files typically start with these bytes
	if len(data) >= 2 && data[0] == 0x30 && (data[1] == 0x82 || data[1] == 0x80 || data[1] == 0x81) {
		// Try to decode with empty password to confirm it's PKCS#12
		_, _, err = pkcs12.Decode(data, "")
		// Even with wrong password, pkcs12.Decode will fail in a specific way for PKCS#12 files
		if err != nil && (err.Error() == "pkcs12: expected exactly two items in the authenticated safe" ||
			bytes.Contains([]byte(err.Error()), []byte("pkcs12")) ||
			bytes.Contains([]byte(err.Error()), []byte("MAC verification failed"))) {
			return "p12", nil
		}
	}

	// Try parsing as DER certificate
	_, err = x509.ParseCertificate(data)
	if err == nil {
		return "der", nil
	}

	return "", errors.New("unknown format")
}

// normalizeFormat converts format aliases to standard names
func normalizeFormat(format string) string {
	switch format {
	case "pkcs12", "pfx":
		return "p12"
	default:
		return format
	}
}
