// Live check against the running stack: client → sample app, and the
// verifier against the live messh key directory.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"

	"messh.io/go/messh"
	"messh.io/go/messh/verify"
)

func check(ok bool, step string, detail any) {
	if !ok {
		fmt.Printf("FAIL go  %s: %v\n", step, detail)
		os.Exit(1)
	}
	fmt.Printf("PASS go  %s\n", step)
}

func main() {
	app, registry, key := os.Getenv("APP"), os.Getenv("REGISTRY"), os.Getenv("KEY")
	client, err := messh.NewClient("mukul", messh.WithKey(messh.KeyFile(key)), messh.WithRegistry(registry))
	check(err == nil, "load key", err)

	resp, err := client.Get(app + "/api/hello")
	check(err == nil, "GET sample app", err)
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	check(resp.StatusCode == 200 && out["key"] == "sdk-test", "GET /api/hello → 200 mukul · sdk-test", out)

	resp, err = client.Post(app+"/api/deploy", "application/json", strings.NewReader(`{"env":"staging"}`))
	check(err == nil, "POST sample app", err)
	b, _ := io.ReadAll(resp.Body)
	check(resp.StatusCode == 200 && strings.Contains(string(b), `"method":"POST"`), "POST /api/deploy with body → 200", string(b))

	v, _ := verify.New(verify.Trust("mukul"), verify.Registry(registry, ""))
	req := httptest.NewRequest("POST", "http://api.example/orders?id=7", strings.NewReader(`{"qty":1}`))
	check(client.Sign(req) == nil, "sign", nil)
	a, err := v.Verify(req)
	check(err == nil && a.Identity == "mukul" && a.KeyName == "sdk-test", "verifier with live messh directory → mukul · sdk-test", err)

	strict, _ := verify.New(verify.Trust("alice"), verify.Registry(registry, ""))
	req = httptest.NewRequest("GET", "http://api.example/x", nil)
	client.Sign(req)
	_, err = strict.Verify(req)
	var ve *verify.Error
	check(errors.As(err, &ve) && ve.Code == "untrusted" && ve.Status == 403, "identity outside trust list → 403 untrusted", err)
}
