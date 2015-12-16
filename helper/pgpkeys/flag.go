package pgpkeys

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// PGPPubKeyFiles implements the flag.Value interface and allows
// parsing and reading a list of pgp public key files
type PubKeyFilesFlag []string

func (p *PubKeyFilesFlag) String() string {
	return fmt.Sprint(*p)
}

func (p *PubKeyFilesFlag) Set(value string) error {
	if len(*p) > 0 {
		return errors.New("pgp-keys can only be specified once")
	}

	splitValues := strings.Split(value, ",")

	keybaseMap, err := FetchKeybasePubkeys(splitValues)
	if err != nil {
		return err
	}

	// Now go through the actual flag, and substitute in resolved keybase
	// entries where appropriate
	for _, keyfile := range splitValues {
		if strings.HasPrefix(keyfile, kbPrefix) {
			key := keybaseMap[keyfile]
			if key == "" {
				return fmt.Errorf("key for keybase user %s was not found in the map", strings.TrimPrefix(keyfile, kbPrefix))
			}
			*p = append(*p, key)
			continue
		}

		pgpStr, err := ReadPGPFile(keyfile)
		if err != nil {
			return err
		}

		*p = append(*p, pgpStr)
	}
	return nil
}

func ReadPGPFile(path string) (string, error) {
	if path[0] == '@' {
		path = path[1:]
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := bytes.NewBuffer(nil)
	_, err = buf.ReadFrom(f)
	if err != nil {
		return "", err
	}

	_, err = base64.StdEncoding.DecodeString(buf.String())
	if err == nil {
		return buf.String(), nil
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil

}
