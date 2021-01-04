# Generating test data

This directory contains the various cryptographic artifacts used by the client
and server in the interop tests. These include:

  1. A root certificate valid for host name "server".
  2. A leaf certificate valid for host name "server", verified by the root certificate.
  3. A delegated credential, verified by the leaf certificate.

(TODO: Use realistic SNIs for the root and leaf certificates, e.g. "ca.com" and
"example.com" respectively.)

(TODO: Generate another leaf certificate for the "client-facing server" in the
ECH protocol.)

(TODO: Generate an ECH config and corresponding key.)

To generate the test data, you'll need to have Go installed and run `make`
within your $GOPATH. I.e., you'll clone this repository into
`$GOPATH/src/github.com/xvzcf/tls-interop-runner`, navigate to this directory,
and run `make`. ($GOPATH is usually `$HOME/go`.)
