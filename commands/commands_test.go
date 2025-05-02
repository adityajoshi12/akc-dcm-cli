package commands_test

import (
	"testing"

	"github.com/adityajoshi12/akc-dcm-cli/commands"
)

func TestAll(t *testing.T) {
	cmds := commands.All()

	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}

	expectedCommands := []string{"certificate", "version"}
	for i, cmd := range cmds {
		if cmd.Use != expectedCommands[i] {
			t.Errorf("expected command %d to be '%s', got '%s'", i, expectedCommands[i], cmd.Use)
		}
	}

	for _, cmd := range cmds {
		if cmd.RunE == nil && len(cmd.Commands()) == 0 {
			t.Errorf("command '%s' has no RunE function or subcommands", cmd.Use)
		}
	}
}
