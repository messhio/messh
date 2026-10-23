// Package apitypes holds the registry JSON the CLI reads and writes.
package apitypes

import (
	"regexp"
	"time"
)

// UsernameRe is the messh username grammar.
var UsernameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$`)

// Profile is GET /<user>.json (and the core of GET /api/v1/me).
type Profile struct {
	Username string    `json:"username"`
	Linked   []Linked  `json:"linked"`
	Agents   []string  `json:"agents"`
	Keys     []Key     `json:"keys"`
	Revoked  []Revoked `json:"revoked"`
	Joined   time.Time `json:"joined"`
}

type Linked struct {
	Provider string `json:"provider"`
	Login    string `json:"login"`
	Verified bool   `json:"verified"`
}

type Key struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	Status      string    `json:"status"`
	Agents      []string  `json:"agents"`
	Added       time.Time `json:"added"`
	Possession  bool      `json:"possession_verified"`
}

type Revoked struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	RevokedAt   time.Time `json:"revoked_at"`
	Reason      string    `json:"reason,omitempty"`
}

type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expires_in"`
}

type DeviceToken struct {
	AccessToken string `json:"access_token"`
	Username    string `json:"username"`
}

type ChallengeRequest struct {
	PublicKey string `json:"public_key"`
}

type Challenge struct {
	ID        string `json:"challenge_id"`
	Namespace string `json:"namespace"`
	Message   string `json:"message"`
}

type PublishRequest struct {
	ChallengeID string   `json:"challenge_id"`
	Signature   string   `json:"signature"`
	Name        string   `json:"name"`
	Agents      []string `json:"agents"`
}

type RevokeRequest struct {
	Reason string `json:"reason"`
}

type Error struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
