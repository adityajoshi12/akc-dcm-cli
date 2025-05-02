package version_test

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/adityajoshi12/akc-dcm-cli/commands/version"
)

func TestNewVersionCommand(t *testing.T) {
	cmd := version.NewVersionCommand()

	// Test with no arguments
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if output.String() == "" {
		t.Fatalf("expected output, got empty string")
	}

	// Test with trailing arguments
	cmd.SetArgs([]string{"unexpected-arg"})
	err = cmd.Execute()
	if err == nil || err.Error() != "trailing args detected" {
		t.Fatalf("expected error 'trailing args detected', got %v", err)
	}
}

func TestGetMetaInfo(t *testing.T) {
	metaInfo := version.GetMetaInfo()

	expectedSubstrings := []string{
		"Version:",
		"Commit SHA:",
		"Go Version:",
		"OS/Arch:",
		runtime.Version(),
		runtime.GOOS + "/" + runtime.GOARCH,
	}

	for _, substring := range expectedSubstrings {
		if !bytes.Contains([]byte(metaInfo), []byte(substring)) {
			t.Errorf("expected meta info to contain %q, but it didn't", substring)
		}
	}
}
