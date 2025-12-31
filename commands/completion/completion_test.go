package completion

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestNewCompletionCommand(t *testing.T) {
	cmd := NewCompletionCommand()
	
	if cmd.Use != "completion [bash|zsh|fish|powershell]" {
		t.Errorf("Expected Use to be 'completion [bash|zsh|fish|powershell]', got %s", cmd.Use)
	}
	
	validArgs := []string{"bash", "zsh", "fish", "powershell"}
	if len(cmd.ValidArgs) != len(validArgs) {
		t.Errorf("Expected %d valid args, got %d", len(validArgs), len(cmd.ValidArgs))
	}
	
	// Verify valid args match
	for i, arg := range validArgs {
		if cmd.ValidArgs[i] != arg {
			t.Errorf("Expected valid arg %s at position %d, got %s", arg, i, cmd.ValidArgs[i])
		}
	}
}

func TestCompletionCommand(t *testing.T) {
	cmd := NewCompletionCommand()
	
	// Create a mock root command
	rootCmd := &cobra.Command{Use: "dcm"}
	rootCmd.AddCommand(cmd)
	
	// Test that the command can be found
	foundCmd, _, err := rootCmd.Find([]string{"completion"})
	if err != nil {
		t.Errorf("Expected to find completion command, got error: %v", err)
	}
	
	if foundCmd.Use != "completion [bash|zsh|fish|powershell]" {
		t.Errorf("Found command has wrong Use: %s", foundCmd.Use)
	}
}

