package awssignature
import (
	"testing"
	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"
	"errors"
)

func TestBackend_basic(t *testing.T) {
	logicaltest.Test(t, logicaltest.TestCase{
		Backend: Backend(),
		Steps: []logicaltest.TestStep{
			testAccStepWriteKey(t),
			testAccStepReadSignature(t),
		},

	})



}

func TestBackend_raw(t *testing.T) {
	logicaltest.Test(t, logicaltest.TestCase{
		Backend: Backend(),
		Steps: []logicaltest.TestStep{
			testAccStepWriteKey(t),
			testAccStepReadRaw(t),
		},

	})



}
func testAccStepWriteKey(t *testing.T) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.WriteOperation,
		Path: "key_name",
		Data: map[string]interface{}{
			"secret_access_key":  "foobar",
		},
	}
}

// The endpoint gives us a signingKey encoded in Base64
func testAccStepReadSignature(t *testing.T) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path: "key_name/20150831/ec2/us-east-1",
		Check: func(resp *logical.Response) error {
			if resp.Data["signature"].(string) != expectedHash {
				err := errors.New("Unexpected hash received from signature endpoint")
				t.Error(err)
				t.Fail()
				return err
			}
			return nil
		},

	}
}

// The endpoint gives us the raw key back
func testAccStepReadRaw(t *testing.T) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path: "raw/key_name",
		Check: func(resp *logical.Response) error {
			if resp.Data["secret_access_key"].(string) != secretKey {
				err := errors.New("Did not receive the correct raw key back")
				t.Error(err)
				t.Fail()
				return err
			}
			return nil
		},

	}
}

const secretKey    = "foobar"
const expectedHash = "Gh6tU3ZoSzIhP6s6jAAL55L8PgB6VVt8pK+W8WYFGl0="
