package certificate

import (
	"github.com/adityajoshi12/akc-dcm-cli/commands/certificate/check"
	"github.com/adityajoshi12/akc-dcm-cli/commands/certificate/inspect"
	"github.com/adityajoshi12/akc-dcm-cli/commands/certificate/renew"
	"github.com/spf13/cobra"
)

func NewCertificateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certificate",
		Short: "The command line interface for certificate management",
	}

	cmd.AddCommand(renew.NewReNewCertificateCommand())
	cmd.AddCommand(check.NewExpireCommand())
	cmd.AddCommand(inspect.NewInspectCommand())

	return cmd
}
