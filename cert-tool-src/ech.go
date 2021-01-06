package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/cryptobyte"

	"github.com/cloudflare/circl/hpke"
)

const (
	ECHVersionDraft09 uint16 = 0xff09 // draft-ietf-tls-esni-09
)

// makeECHKey generates an ECH config and corresponding key, writing the key to
// outKeyPath and the config to outPath. The config is encoded as an ECHConfigs
// structure as specified by draft-ietf-tls-esni-09 (i.e., it is prefixed by
// 16-bit integer that encodes its length). This is the format as it is consumed
// by the client.
//
// The first DNS name of certificate inCertPath is used as the ECH config's
// public name. The remaining parameters of the ECH config are specified by the
// template.
func makeECHKey(template ECHConfigTemplate, inCertPath, outPath, outKeyPath string) {
	certParseErrMsg := "failed to parse input certificate"
	keyGenErrMsg := "failed to generate ECH key"

	// Load the certificate of the client-facing server.
	clientFacingCertPEMBlock, err := ioutil.ReadFile(filepath.Join(inCertPath))
	fatalIfErr(err, certParseErrMsg)
	clientFacingCertDERBlock, _ := pem.Decode(clientFacingCertPEMBlock)
	if clientFacingCertDERBlock == nil || clientFacingCertDERBlock.Type != "CERTIFICATE" {
		fatalIfErr(errors.New("PEM decoding failed"), certParseErrMsg)
	}
	clientFacingCert, err := x509.ParseCertificate(clientFacingCertDERBlock.Bytes)
	fatalIfErr(err, certParseErrMsg)

	// Generate the ECH config and corresponding key, using the first DNS name
	// specified by the client-facing certificate as the public name.
	//
	// TODO(cjpatton): Assert that clientFAcingCert.DNSNames[0] is a valid SNI
	// (e.g., not something like *.example.com).
	if len(clientFacingCert.DNSNames) == 0 {
		fatalIfErr(errors.New("input certificate does not specify a DNS name"), keyGenErrMsg)
	}
	template.PublicName = clientFacingCert.DNSNames[0]
	key, err := GenerateECHKey(template)
	fatalIfErr(err, keyGenErrMsg)

	// Write the key to disk.
	outKey, err := os.OpenFile(outKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	fatalIfErr(err, keyGenErrMsg)
	defer outKey.Close()
	outKeyEncoder := base64.NewEncoder(base64.StdEncoding, outKey)
	defer outKeyEncoder.Close()
	_, err = outKeyEncoder.Write(key.Marshal())
	fatalIfErr(err, keyGenErrMsg)

	// Write the config to disk.
	out, err := os.Create(outPath)
	fatalIfErr(err, keyGenErrMsg)
	defer out.Close()
	outEncoder := base64.NewEncoder(base64.StdEncoding, out)
	defer outEncoder.Close()
	_, err = outEncoder.Write(MarshalECHConfigs([]ECHKey{*key}))
	fatalIfErr(err, keyGenErrMsg)
}

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
		return nil, fmt.Errorf("failed to marshal KEM secert key: %s", err)
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
