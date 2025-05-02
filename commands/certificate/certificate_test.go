package certificate_test

import (
	"bytes"
	"testing"

	"github.com/adityajoshi12/akc-dcm-cli/commands/certificate"
)

func TestNewCertificateCommand(t *testing.T) {
	cmd := certificate.NewCertificateCommand()

	if cmd.Use != "certificate" {
		t.Errorf("expected command use to be 'certificate', got %s", cmd.Use)
	}

	if cmd.Short != "The command line interface for certificate management" {
		t.Errorf("expected command short description to be 'The command line interface for certificate management', got %s", cmd.Short)
	}

	subCommands := []string{"renew", "check", "inspect"}
	for _, subCmd := range subCommands {
		found := false
		for _, c := range cmd.Commands() {
			if c.Use == subCmd {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand '%s' not found", subCmd)
		}
	}

	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
