package messh

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"messh.io/go/messh/httpsig"
	"messh.io/go/messh/internal/wba"
)

// DirectoryTag tags the signatures on a key directory response.
const DirectoryTag = "http-message-signatures-directory"

// DirectoryResponse builds a key directory for keys, to serve yourself at
// https://<authority>/.well-known/http-message-signatures-directory, and the
// headers that sign it: Content-Digest, and one signature per key binding the
// directory to authority (draft-meunier-http-message-signatures-directory §5),
// the form Cloudflare's tools check. Build it again before created+ttl.
func DirectoryResponse(authority string, keys []KeySource, created time.Time, ttl time.Duration) (body []byte, header http.Header, err error) {
	signers := make([]Signer, len(keys))
	jwks := make([]string, len(keys))
	for i, k := range keys {
		if signers[i], err = k(); err != nil {
			return nil, nil, err
		}
		pub := signers[i].Public()
		jwks[i] = `{"kty":"OKP","crv":"Ed25519","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `","kid":"` + wba.Thumbprint(pub) + `"}`
	}
	body = []byte(`{"keys":[` + strings.Join(jwks, ",") + `]}`)
	header = http.Header{}
	header.Set("Content-Type", "application/http-message-signatures-directory+json")
	header.Set("Content-Digest", httpsig.ContentDigest(body))
	resp := &httpsig.Message{Status: http.StatusOK, Header: header,
		Request: &httpsig.Message{Method: "GET", Scheme: "https", Authority: authority, Path: wba.DirectoryPath, Header: http.Header{}}}
	created = time.Unix(created.Unix(), 0)
	for i, s := range signers {
		signed, err := httpsig.Sign(resp, s, httpsig.SignOptions{Label: fmt.Sprintf("binding%d", i),
			Components: []string{`"@authority";req`, "content-digest"}, Created: created, Expires: created.Add(ttl),
			KeyID: wba.Thumbprint(s.Public()), Alg: "ed25519", Tag: DirectoryTag})
		if err != nil {
			return nil, nil, &Error{"sign_failed", err.Error()}
		}
		signed.AddTo(header)
	}
	return body, header, nil
}
