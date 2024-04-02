package commands

import (
	"github.com/adityajoshi12/akc-dcm-cli/commands/certificate"
	"github.com/adityajoshi12/akc-dcm-cli/commands/version"
	"github.com/spf13/cobra"
)

func All() []*cobra.Command {
	return []*cobra.Command{
		certificate.NewCertificateCommand(),
		version.NewVersionCommand(),
	}
}
