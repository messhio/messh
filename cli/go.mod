module github.com/messhio/messh/cli

go 1.26.0

require messh.io/go/messh v0.1.0

require (
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0 // indirect
)

// The SDK lives in this repo; build against it directly.
replace messh.io/go/messh => ../sdk/go
