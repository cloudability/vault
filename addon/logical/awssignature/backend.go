package awssignature

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"crypto/hmac"
	"crypto/sha256"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// logical.Factory
func Factory(*logical.BackendConfig) (logical.Backend, error) {
	return Backend(), nil
}

func Backend() *framework.Backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(awssignatureHelp),

		PathsSpecial: &logical.Paths{
			Root: []string{
				"raw/*",
			},
		},

		Paths: []*framework.Path{
			pathStandardKey(&b),
			pathWriteStandardKey(&b),
			pathReadRawKey(&b),
		},
	}

	return b.Backend

}

type backend struct {
	*framework.Backend
}

func Fields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"key_id": &framework.FieldSchema{
			Type:        framework.TypeString,
			Description: "Unique ID of the key",
		},
		"secret_access_key": &framework.FieldSchema{
			Type:        framework.TypeString,
			Description: "AWS Secret Access Key",
		},
		"date": &framework.FieldSchema{
			Type:        framework.TypeString,
			Description: "Date string used for V4 signing",
		},

		"service_name": &framework.FieldSchema{
			Type:        framework.TypeString,
			Description: "Service string used for V4 signing",
		},

		"region_name": &framework.FieldSchema{
			Type:        framework.TypeString,
			Description: "Region string used for V4 signing",
		},
	}
}

func pathReadRawKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "raw/" + framework.GenericNameRegex("key_id"),
		Fields:  Fields(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.handleRawRead,
		},
	}
}
func pathWriteStandardKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: framework.GenericNameRegex("key_id"),
		Fields:  Fields(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.WriteOperation:  b.handleWrite,
			logical.ReadOperation:   b.handleRead,
			logical.DeleteOperation: b.handleDelete,
		},
	}
}

func pathStandardKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: framework.GenericNameRegex("key_id") +
			"/" + framework.GenericNameRegex("date") +
			"/" + framework.GenericNameRegex("service_name") +
			"/" + framework.GenericNameRegex("region_name"),
		Fields: Fields(),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.handleRead,
		},
	}
}

func (b *backend) handleWrite(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Check that some fields are given
	if len(req.Data) == 0 {
		return nil, fmt.Errorf("missing data fields")
	}

	// JSON encode the data
	buf, err := json.Marshal(req.Data)
	if err != nil {
		return nil, fmt.Errorf("json encoding failed: %v", err)
	}

	// Write out a new key
	entry := &logical.StorageEntry{
		Key:   req.Path,
		Value: buf,
	}

	if err := req.Storage.Put(entry); err != nil {
		return nil, fmt.Errorf("failed to write: %v", err)
	}

	return nil, nil
}

func (b *backend) handleDelete(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Delete the key at the request path
	if err := req.Storage.Delete(req.Path); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) handleRead(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Read the path
	out, err := req.Storage.Get(data.Raw["key_id"].(string))
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}

	// Fast-path the no data case
	if out == nil {
		return nil, nil
	}

	// Decode the data
	var rawData map[string]interface{}
	if err := json.Unmarshal(out.Value, &rawData); err != nil {
		return nil, fmt.Errorf("json decoding failed: %v", err)
	}

	key := rawData["secret_access_key"].(string)
	datestamp := data.Get("date").(string)
	regionName := data.Get("region_name").(string)
	serviceName := data.Get("service_name").(string)
	signingKey := buildSignature(key, datestamp, regionName, serviceName)
	b64Key := base64.StdEncoding.EncodeToString(signingKey)

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": b64Key,
		},
	}, nil
}

func (b *backend) handleRawRead(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Read the path
	newPath := strings.Replace(req.Path, "raw/", "", 1)
	out, err := req.Storage.Get(newPath)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}

	// Fast-path the no data case
	if out == nil {
		return nil, nil
	}

	// Decode the data
	var rawData map[string]interface{}
	if err := json.Unmarshal(out.Value, &rawData); err != nil {
		return nil, fmt.Errorf("json decoding failed: %v", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"secret_access_key": rawData["secret_access_key"],
		},
	}, nil
}

func makeHmac(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func buildSignature(secretKey string, datestamp string, regionName string, serviceName string) []byte {
	date := makeHmac([]byte("AWS4"+secretKey), []byte(datestamp))
	region := makeHmac(date, []byte(regionName))
	service := makeHmac(region, []byte(serviceName))
	signingKey := makeHmac(service, []byte("aws4_request"))
	return signingKey
}

const awssignatureHelp = ``
