package utilities

import (
	"encoding/json"
	"os"
	"os/user"
	"strings"

	"github.com/adityajoshi12/akc-dcm-cli/glossary"
	"github.com/pkg/errors"
)

// WriteFileToLocal to write data into local storage
func WriteFileToLocal(filePath string, data []byte) error {
	usr, err := user.Current()
	if err != nil {
		return errors.WithMessage(err, "WriteFileToLocal - Unable to get current user")
	}

	if _, err := os.Stat(usr.HomeDir + "/" + glossary.DefaultOutputPath); os.IsNotExist(err) {
		err := os.MkdirAll(usr.HomeDir+"/"+glossary.DefaultOutputPath, 0755)
		if err != nil {
			return errors.WithMessage(err, "WriteFileToLocal - Unable to make default output folder")
		}
	}

	if strings.Contains(filePath, ".dcm") {
		filePath = usr.HomeDir + "/" + filePath
	}

	file, err := os.Create(filePath)
	if err != nil {
		return errors.WithMessage(err, "Unable to create file")
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return errors.WithMessage(err, "Unable to write data to file")
	}

	return nil
}

// WriteJsonFileToLocal to write json cert struct into local storage
func WriteJsonFileToLocal(filePath string, jCert interface{}) error {
	jsByte, err := json.Marshal(jCert)
	if err != nil {
		return errors.WithMessage(err, "WriteJsonFileToLocal - Unable to marshal json of data")
	}

	return WriteFileToLocal(filePath, jsByte)
}
