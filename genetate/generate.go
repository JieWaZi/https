package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var (
	caDir                 string
	caCommonName          string
	caCountryName         string
	caOrganization        string
	caOrganizationalUnit  string
	caStateOrProvinceName string
	caEmailAddress        string

	currentDir string
)

func init() {
	flag.StringVar(&caDir, "caDir", "CA", "Store CA Path")
	flag.StringVar(&caCommonName, "caCommonName", "Root Certificate Authority", "CA Common Name")
	flag.StringVar(&caCountryName, "caCountryName", "AU", "CA Country Name")
	flag.StringVar(&caOrganization, "caOrganization", "Organization", "CA Organization")
	flag.StringVar(&caOrganizationalUnit, "caOrganizationalUnit", "OrganizationalUnit", "CA Organizational Unit")
	flag.StringVar(&caStateOrProvinceName, "caStateOrProvinceName", "NSW", "CA State Or Province Name")
	flag.StringVar(&caEmailAddress, "caEmailAddress", "nobody@email.com", "CA Email Address")

	currentDir, _ := os.Getwd()
	os.MkdirAll(filepath.Join(currentDir, caDir), 0700)
}

func GenRootCA() {
	var rootTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         caCommonName,
			Country:            []string{caCountryName},
			Organization:       []string{caOrganization},
			OrganizationalUnit: []string{caOrganizationalUnit},
			Province:           []string{caStateOrProvinceName},
			StreetAddress:      []string{caEmailAddress},
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		MaxPathLen:            2,
	}

	// private key
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	priBytes, err := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	if err != nil {
		fmt.Printf("marshal PKCS8 private key err: %s \n", err)
		panic(err)
	}
	privatePem, err := os.Create(filepath.Join(caDir, "ca.key"))
	if err != nil {
		fmt.Printf("error when create ca.pem: %s \n", err)
		panic(err)
	}
	privateKeyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: priBytes}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		fmt.Printf("error when encode private: %s \n", err)
		panic(err)
	}

	// certificate
	_, certBlock, err := genCert(&rootTemplate, &rootTemplate, &rsaPrivateKey.PublicKey, rsaPrivateKey)
	caCrt, err := os.Create(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		fmt.Printf("error when create ca.crt: %s \n", err)
		panic(err)
	}
	err = pem.Encode(caCrt, certBlock)
	if err != nil {
		fmt.Printf("error when encode ca crt: %s \n", err)
		panic(err)
	}

	// public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		fmt.Printf("error when dumping publickey: %s \n", err)
		panic(err)
	}
	publicKeyBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}
	publicPem, err := os.Create(filepath.Join(caDir, "ca.pem"))
	if err != nil {
		fmt.Printf("error when create public.pem: %s \n", err)
		panic(err)
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		fmt.Printf("error when create public.pem: %s \n", err)
		panic(err)
	}
}

func GenServerCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, domains []string) (*x509.Certificate, *pem.Block, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	var serverTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            nil,
			Organization:       nil,
			OrganizationalUnit: nil,
			Locality:           nil,
			Province:           nil,
			StreetAddress:      nil,
			PostalCode:         nil,
			SerialNumber:       "",
			CommonName:         "",
		},
		NotBefore:          time.Now().Add(-10 * time.Second),
		NotAfter:           time.Now().AddDate(10, 0, 0),
		KeyUsage:           x509.KeyUsageCRLSign,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: x509.SHA256WithRSA,
		IsCA:               false,
		MaxPathLenZero:     true,
		DNSNames:           domains,
	}

	serverCert, serverBlock, err := genCert(&serverTemplate, caCert, &privateKey.PublicKey, caKey)
	return serverCert, serverBlock, privateKey
}

func genCert(template, parent *x509.Certificate, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (*x509.Certificate, *pem.Block, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}, nil
}

func main() {

}
