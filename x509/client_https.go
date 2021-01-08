package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func main() {
	cert, err := tls.LoadX509KeyPair("./keys/client/client_cert.pem", "./keys/client/private/client_key.pem")
	if err != nil {
		log.Println(err)
		return
	}
	certBytes, err := ioutil.ReadFile("./keys/ca/ca_cert.pem")
	if err != nil {
		panic("Unable to read cert.pem")
	}
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(certBytes)
	if !ok {
		panic("failed to parse root certificate")
	}
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 0,
			}).DialContext,
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{cert},
			}},
	}

	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://server.tls.example.com:443"), strings.NewReader("hello"))

	resp, err := c.Do(req)
	if err != nil {
		panic(err)
	}
	s, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(s))
}
