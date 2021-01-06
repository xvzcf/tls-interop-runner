package main

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"

	"github.com/cloudflare/circl/hpke"
)

const (
	ECHVersionDraft09 uint16 = 0xfe09 // draft-ietf-tls-esni-09
)

// ECHConfigTemplate defines the parameters for generating an ECH config and
// corresponding key.
type ECHConfigTemplate struct {
	// The version of ECH to use for this configuration.
	Version uint16

	// The name of the client-facing server.
	PublicName string

	// The algorithm used for the KEM key pair. Available algorithms are
	// enumerated in this package.
	KemId uint16

	// The KDF algorithms the server for this configuration.
	KdfIds []uint16

	// The AEAD algorithms the server offers for this configuration.
	AeadIds []uint16

	// The maximum length of any server name in the anonymity set. In the ECH
	// extension, the ClientHelloInner is padded to this length in order to
	// protect the server name. This value may be 0, in which case the default
	// padding is used.
	MaximumNameLength uint16

	// Extensions to add to the end of the configuration. This implementation
	// currently doesn't handle extensions, but this field is useful for testing
	// purposes.
	Extensions []byte
}

// ECHKey represents an ECH config and its corresponding key. The encoding of an
// ECH Key has the format defined below (in TLS syntax). Note that the ECH
// standard does not specify this format.
//
// struct {
//     opaque sk<0..2^16-1>;
//     ECHConfig config<0..2^16>; // draft-ietf-tls-esni-09
// } ECHKey;
type ECHKey struct {
	sk []byte

	// The serialized ECHConfig.
	Config []byte
}

// GenerateECHKey generates an ECH config and corresponding key using the
// parameters specified by template.
func GenerateECHKey(template ECHConfigTemplate) (*ECHKey, error) {
	if template.Version != ECHVersionDraft09 {
		return nil, errors.New("template version not supported")
	}

	kem := hpke.KEM(template.KemId)
	if !kem.IsValid() {
		return nil, errors.New("KEM algorithm not supported")
	}

	pk, sk, err := kem.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("KEM key generation failed: %s", err)
	}

	publicKey, err := pk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal KEM public key: %s", err)
	}

	secretKey, err := sk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal KEM secret key: %s", err)
	}

	var c cryptobyte.Builder
	c.AddUint16(template.Version)
	c.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { // contents
		c.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
			c.AddBytes([]byte(template.PublicName))
		})
		c.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
			c.AddBytes(publicKey)
		})
		c.AddUint16(template.KemId)
		c.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
			for _, kdfId := range template.KdfIds {
				for _, aeadId := range template.AeadIds {
					c.AddUint16(kdfId)
					c.AddUint16(aeadId)
				}
			}
		})
		c.AddUint16(template.MaximumNameLength)
		c.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
			c.AddBytes(template.Extensions)
		})
	})

	return &ECHKey{secretKey, c.BytesOrPanic()}, nil
}

// Marshal returns the serialized ECH key.
func (key ECHKey) Marshal() []byte {
	var k cryptobyte.Builder
	k.AddUint16LengthPrefixed(func(k *cryptobyte.Builder) {
		k.AddBytes(key.sk)
	})
	k.AddUint16LengthPrefixed(func(k *cryptobyte.Builder) {
		k.AddBytes(key.Config)
	})
	return k.BytesOrPanic()
}

// MarshalECHConfigs returns the serialized ECHConfigs corresponding to a
// sequence of ECH keys.
func MarshalECHConfigs(keys []ECHKey) []byte {
	var c cryptobyte.Builder
	c.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
		for _, key := range keys {
			c.AddBytes(key.Config)
		}
	})
	return c.BytesOrPanic()
}
