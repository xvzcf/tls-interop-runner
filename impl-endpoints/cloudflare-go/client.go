package main

import (
    "log"
    "fmt"
    "crypto/x509"
    "crypto/tls"
    "io/ioutil"
)

func main() {
    certPool := x509.NewCertPool()
    pem, err := ioutil.ReadFile("/certs/rootCA.pem")
    certPool.AppendCertsFromPEM(pem)

    conf := &tls.Config{
         RootCAs: certPool,
         SupportDelegatedCredential: true,
    }

    conn, err := tls.Dial("tcp", "server:4433", conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()

    n, err := conn.Write([]byte("hello\n"))
    if err != nil {
        log.Println(n, err)
        return
    }

    certs := conn.ConnectionState().PeerCertificates

    for _, cert := range certs {
        fmt.Printf("Issuer Name: %s\n", cert.Issuer)
        fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
        fmt.Printf("Cert Serial Number: %v \n", cert.SerialNumber)
        fmt.Printf("DC: %#v \n", conn.ConnectionState().VerifiedDC)
    }
}
