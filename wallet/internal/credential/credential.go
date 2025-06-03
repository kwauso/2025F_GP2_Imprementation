// Package credential defines the structures and types used for handling credentials in the wallet system.
// It includes definitions for credential entries, presentations, subjects, and related metadata.
package credential

import (
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type SupportedSerializationFlavor string // mime type

const (
	JwtVc      SupportedSerializationFlavor = "application/vc+jwt"
	MockFormat SupportedSerializationFlavor = "plain/mock" // For testing
)

type Credential struct {
	ID          *url.URL
	Types       []string
	Name        *string
	Description *string
	Issuer      url.URL
	Subjects    []CredentialSubject
	ValidPeriod *CredentialValidPeriod
	Status      *CredentialStatus
	Schemas     *[]CredentialSchema
	Proof       *CredentialProof
}

type CredentialPresentation struct {
	ID          *url.URL
	Types       []string
	Credentials [][]byte
	Holder      *url.URL
	Proof       *CredentialProof
	Nonce       *string
}

type CredentialSubject struct {
	ID     *url.URL
	Claims map[string]interface{}
}

type CredentialValidPeriod struct {
	From *time.Time
	To   *time.Time
}

type CredentialStatus struct{}

type CredentialSchema struct{}

type CredentialProof struct {
	Algorithm jose.SignatureAlgorithm `json:"alg"`
	Signature []byte                  `json:"signature"`
	Payload   []byte                  `json:"payload"`
}
