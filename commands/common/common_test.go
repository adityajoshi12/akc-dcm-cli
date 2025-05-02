package common_test

import (
	"testing"

	"github.com/adityajoshi12/akc-dcm-cli/commands/common"
	"github.com/spf13/cobra"
)

func TestParseArgs(t *testing.T) {
	var arg1, arg2 string
	cmd := common.Command{}
	cmd.AddArg(&arg1)
	cmd.AddArg(&arg2)

	positionalArgs := cmd.ParseArgs()

	// Test with valid arguments
	args := []string{"value1", "value2"}
	err := positionalArgs(&cobra.Command{}, args)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if arg1 != "value1" {
		t.Errorf("expected arg1 to be 'value1', got '%s'", arg1)
	}

	if arg2 != "value2" {
		t.Errorf("expected arg2 to be 'value2', got '%s'", arg2)
	}

	// Test with fewer arguments than expected
	args = []string{"value1"}
	err = positionalArgs(&cobra.Command{}, args)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if arg1 != "value1" {
		t.Errorf("expected arg1 to be 'value1', got '%s'", arg1)
	}

	if arg2 != "" {
		t.Errorf("expected arg2 to be empty, got '%s'", arg2)
	}
}
