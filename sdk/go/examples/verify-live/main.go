// verify-live signs a request as IDENTITY with KEY and verifies it against
// the live messh key directory at REGISTRY, the way an API would.
//
//	REGISTRY=http://localhost:8080 IDENTITY=mukul KEY=~/.ssh/id_ed25519 go run ./examples/verify-live
package main

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"

	"messh.io/go/messh"
	"messh.io/go/messh/verify"
)

func main() {
	registry, identity, key := os.Getenv("REGISTRY"), os.Getenv("IDENTITY"), os.Getenv("KEY")
	client, err := messh.NewClient(identity, messh.WithKey(messh.KeyFile(key)), messh.WithRegistry(registry))
	if err != nil {
		fail("load key", err)
	}
	v, err := verify.New(verify.Trust(identity), verify.Registry(registry, os.Getenv("FETCH_BASE")))
	if err != nil {
		fail("verifier", err)
	}
	req := httptest.NewRequest("POST", "https://api.example.com/deploy?env=staging", strings.NewReader(`{"ref":"main"}`))
	if err := client.Sign(req); err != nil {
		fail("sign", err)
	}
	a, err := v.Verify(req)
	if err != nil {
		fail("verify", err)
	}
	fmt.Printf("verified %s · key %s · keyid %s\n", a.Identity, a.KeyName, a.KeyID)

	if _, err := v.Verify(req); !isCode(err, "nonce_replayed") {
		fail("replay must be rejected", err)
	}
	fmt.Println("replay rejected")
}

func isCode(err error, code string) bool {
	var ve *verify.Error
	return errors.As(err, &ve) && ve.Code == code
}

func fail(step string, err error) {
	fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", step, err)
	os.Exit(1)
}
