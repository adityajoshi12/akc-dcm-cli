package inspect

import (
	"github.com/adityajoshi12/akc-dcm-cli/commands/common"
	"github.com/adityajoshi12/akc-dcm-cli/utilities"
	"fmt"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewInspectCommand() *cobra.Command {
	c := InspectCommand{}

	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect certificate",
		Long:  "Parse detail of certificate",
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
	flags.StringVarP(&c.CertPath, "cert", "c", "", "Path to your certificate")

	return cmd
}

type InspectCommand struct {
	common.Command
	CertPath string
}

// Validate checks the required parameters for run
func (c *InspectCommand) Validate() error {
	if len(c.CertPath) == 0 {
		return errors.New("Certificate path is required")
	}

	return nil
}

// Run executes the command
func (c *InspectCommand) Run() error {
	cert, isJson, err := utilities.ParseCertificate(c.CertPath)
	if err != nil {
		return err
	}

	if isJson {
		jCert, err := utilities.ParseJsonCert(c.CertPath)
		if err != nil {
			return err
		}
		fmt.Println(fmt.Sprintf("Signing Identity: %s", jCert.Enrollment.SigningIdentity))
	}

	textFormat, err := utilities.CertificateText(cert)
	if err != nil {
		return err
	}

	fmt.Println(textFormat)

	return nil
}
