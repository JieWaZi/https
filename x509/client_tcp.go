package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
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
	conf := &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}

	conn, err := tls.Dial("tcp", "server.tls.example.com:443", conf)
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
	buf := make([]byte, 100)
	n, err = conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		return
	}
	println(string(buf[:n]))
}
