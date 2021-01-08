package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main() {
	s := &http.Server{
		Addr:           fmt.Sprintf(":%d", 443),
		Handler:        apiForwardHandler(),
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxHeaderBytes: 1024 * 1024,
	}

	log.Printf("api server listen and serve on :%d\n", 443)
	log.Fatal(s.ListenAndServeTLS("./keys/server/server_cert.pem", "./keys/server/private/server_key.pem"))
}

func apiForwardHandler() http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		data, _ := ioutil.ReadAll(req.Body)
		fmt.Println(string(data))
		rw.WriteHeader(200)
		rw.Write([]byte("world"))
	}
}
