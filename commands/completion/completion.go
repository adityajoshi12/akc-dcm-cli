package completion

import (
	"os"

	"github.com/spf13/cobra"
)

func NewCompletionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for dcm.

To load completions:

Bash:

  $ source <(dcm completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ dcm completion bash > /etc/bash_completion.d/dcm
  # macOS:
  $ dcm completion bash > $(brew --prefix)/etc/bash_completion.d/dcm

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ dcm completion zsh > "${fpath[1]}/_dcm"

  # You will need to start a new shell for this setup to take effect.

Fish:

  $ dcm completion fish | source

  # To load completions for each session, execute once:
  $ dcm completion fish > ~/.config/fish/completions/dcm.fish

PowerShell:

  PS> dcm completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> dcm completion powershell > dcm.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletion(os.Stdout)
			}
			return nil
		},
	}

	return cmd
}
