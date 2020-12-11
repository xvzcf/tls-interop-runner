package main

import (
    "log"
    "fmt"
    "crypto/x509"
    "crypto/tls"
    "time"
    "io/ioutil"
)

func main() {
    certPool := x509.NewCertPool()
    pem, err := ioutil.ReadFile("/root.pem")
    certPool.AppendCertsFromPEM(pem)

    now := func() time.Time { return time.Unix(1593608733, 0) }
    conf := &tls.Config{
         RootCAs: certPool,
         Time: now,
         SupportDelegatedCredential: true,
         InsecureSkipVerify: true,
    }

    conn, err := tls.Dial("tcp", "bssl-server:4433", conf)
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
    }
}
