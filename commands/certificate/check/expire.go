package check

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adityajoshi12/akc-dcm-cli/commands/common"
	"github.com/adityajoshi12/akc-dcm-cli/utilities"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewExpireCommand() *cobra.Command {
	c := ExpireCommand{}

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Checking expiration date",
		Long:  "Checking expiration date of certificate",
		Args:  c.ParseArgs(),
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if err := c.Validate(); err != nil {
				return err
			}

			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return c.Run()
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&c.CertPath, "cert-path", "c", "", "Path to your certificate")
	flags.StringVarP(&c.FolderPath, "folder-cert", "f", "", "Path to folder have certificates")
	flags.StringVarP(&c.Domain, "domain", "d", "", "Domain to check certificate expiry (e.g. example.com or example.com:8443)")

	return cmd
}

type ExpireCommand struct {
	common.Command
	CertPath   string
	FolderPath string
	Domain     string
}

// Validate checks the required parameters for run
func (c *ExpireCommand) Validate() error {
	if len(c.CertPath) == 0 && len(c.FolderPath) == 0 && len(c.Domain) == 0 {
		return errors.New("File certificate, Folder have certificate, or Domain is required")
	}

	return nil
}

// Run executes the command
func (c *ExpireCommand) Run() error {
	if len(c.CertPath) > 0 {
		return checkExpireCert(c.CertPath)
	} else if len(c.Domain) > 0 {
		return checkExpireDomain(c.Domain)
	} else {
		err := filepath.Walk(c.FolderPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return errors.WithMessage(err, "Failed to scan certificate dir")
			}
			if !info.IsDir() {
				err = checkExpireCert(path)
				if err != nil {
					fmt.Println(fmt.Sprintf("Unable to check expire date of \"%s\" certificate", path))
				}
			}
			return nil
		})
		if err != nil {
			return errors.WithMessage(err, "Failed to scan certificate dir")
		}
	}
	return nil
}

func checkExpireCert(certPath string) error {
	cert, _, err := utilities.ParseCertificate(certPath)
	if err != nil {
		return err
	}

	fileName := filepath.Base(certPath)
	fmt.Println("Certificate", color.YellowString("%s - path (%s)", fileName, certPath), "will be expire at", color.YellowString("%s", cert.NotAfter.String()))
	if cert.NotAfter.Before(time.Now()) {
		fmt.Println("Certificate", color.RedString("%s - path (%s) was expired!!!", fileName, certPath))
	} else {
		fmt.Println("Certificate", color.GreenString("%s - path (%s) is good today.", fileName, certPath))
	}

	return nil
}

func checkExpireDomain(domain string) error {
	if len(domain) == 0 {
		return errors.New("Domain is required")
	}
	address := domain
	if !strings.Contains(domain, ":") {
		address = domain + ":443"
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return errors.Wrapf(err, "Failed to connect to domain %s", address)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return errors.Errorf("No certificates found for domain %s", address)
	}
	cert := certs[0]
	fmt.Println("Domain", color.YellowString("%s", address), "certificate will expire at", color.YellowString("%s", cert.NotAfter.String()))
	if cert.NotAfter.Before(time.Now()) {
		fmt.Println("Domain", color.RedString("%s certificate was expired!!!", address))
	} else {
		fmt.Println("Domain", color.GreenString("%s certificate is good today.", address))
	}
	return nil
}
