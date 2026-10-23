# messh CLI and SDKs. Everything runs in Docker.
# Compared byte for byte; go test checks test_ed25519, whose OpenSSH encoding has random check bytes.
VECTORS := test_ed25519.pub test_ed25519.pkcs8.pem web-bot-auth.json

test: test-cli test-sdk vectors

test-cli:      ## CLI vet and tests
	docker run --rm -v "$(CURDIR)":/w -w /w/cli golang:1.26-alpine sh -c 'go vet ./... && go test ./...'
test-sdk:      ## all five SDKs against spec/vectors
	sdk/test.sh
vectors:       ## the reference implementation's tests, and spec/vectors is exactly what it writes
	docker run --rm -v "$(CURDIR)":/w -w /w/spec/vectors/gen -e GOWORK=off golang:1.26-alpine sh -c \
	  'go vet ./... && go test ./... && go run . /tmp/v && for f in $(VECTORS); do cmp /tmp/v/$$f ../$$f || exit 1; done && echo "spec/vectors is up to date"'
.PHONY: test test-cli test-sdk vectors
