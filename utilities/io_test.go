package utilities_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/adityajoshi12/akc-dcm-cli/utilities"
)

func TestWriteJsonFileToLocal(t *testing.T) {
	tempFile, err := os.CreateTemp("", "test-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tempFile.Close()
	defer os.Remove(tempFile.Name())

	testData := map[string]string{
		"key": "value",
	}

	err = utilities.WriteJsonFileToLocal(tempFile.Name(), testData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	fileContent, err := os.ReadFile(tempFile.Name())
	if err != nil {
		t.Fatalf("failed to read temp file: %v", err)
	}

	var result map[string]string
	err = json.Unmarshal(fileContent, &result)
	if err != nil {
		t.Fatalf("failed to unmarshal file content: %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("expected key 'value', got '%s'", result["key"])
	}
}
