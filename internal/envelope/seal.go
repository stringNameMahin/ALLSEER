package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// Sealing errors.
var (
	ErrAlreadySealed = errors.New("envelope: already sealed; a changed envelope needs a new one, not a re-seal")
	ErrNotSealed     = errors.New("envelope: not sealed")
	ErrTampered      = errors.New("envelope: digest does not match content")
)

// DigestSealer seals with a SHA-256 over the envelope's JSON encoding.
//
// The encoding is Go's encoding/json of ece.Envelope: struct fields in
// declaration order, map keys sorted, floats in shortest form, times in
// RFC 3339. Digest and Approval are excluded, since the approval record is
// written onto the envelope after sealing.
type DigestSealer struct{}

var _ Sealer = DigestSealer{}

// Seal marks env sealed and records its digest. It refuses an envelope that
// is already sealed.
func (DigestSealer) Seal(env *ece.Envelope) error {
	if env == nil {
		return errors.New("envelope: nil envelope")
	}
	if env.Sealed {
		return ErrAlreadySealed
	}
	env.Sealed = true
	d, err := Digest(env)
	if err != nil {
		env.Sealed = false
		return err
	}
	env.Digest = d
	return nil
}

// Verify checks that a sealed envelope still matches its digest.
func (DigestSealer) Verify(env *ece.Envelope) error {
	if env == nil || !env.Sealed || env.Digest == "" {
		return ErrNotSealed
	}
	d, err := Digest(env)
	if err != nil {
		return err
	}
	if d != env.Digest {
		return fmt.Errorf("%w: have %s, computed %s", ErrTampered, env.Digest, d)
	}
	return nil
}

// Digest computes the content hash of env.
func Digest(env *ece.Envelope) (string, error) {
	c := *env
	c.Digest = ""
	c.Approval = nil
	b, err := json.Marshal(&c)
	if err != nil {
		return "", fmt.Errorf("envelope: encoding for digest: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
