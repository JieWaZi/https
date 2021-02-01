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

	dns    string
	output string
	shell  string
)

func init() {
	flag.StringVar(&caDir, "caDir", "CA", "Store CA Path")
	flag.StringVar(&caCommonName, "caCommonName", "Root Certificate Authority", "CA Common Name")
	flag.StringVar(&caCountryName, "caCountryName", "AU", "CA Country Name")
	flag.StringVar(&caOrganization, "caOrganization", "Organization", "CA Organization")
	flag.StringVar(&caOrganizationalUnit, "caOrganizationalUnit", "OrganizationalUnit", "CA Organizational Unit")
	flag.StringVar(&caStateOrProvinceName, "caStateOrProvinceName", "NSW", "CA State Or Province Name")
	flag.StringVar(&caEmailAddress, "caEmailAddress", "nobody@email.com", "CA Email Address")
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
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey)})
	_, certPEM := genCert(&rootTemplate, &rootTemplate, &rsaPrivateKey.PublicKey, rsaPrivateKey)

	fmt.Println(string(keyPEM))
	fmt.Println(string(certPEM))
}

func GenServerCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, domains []string) (*x509.Certificate, []byte, *rsa.PrivateKey) {
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
		NotBefore:      time.Now().Add(-10 * time.Second),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		KeyUsage:       x509.KeyUsageCRLSign,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:           false,
		MaxPathLenZero: true,
		DNSNames:       domains,
	}

	serverCert, serverPEM := genCert(&serverTemplate, caCert, &privateKey.PublicKey, caKey)
	return serverCert, serverPEM, privateKey

}

func genCert(template, parent *x509.Certificate, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (*x509.Certificate, []byte) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		panic("Failed to create certificate:" + err.Error())
	}
	
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		panic("Failed to parse certificate:" + err.Error())
	}

	b := pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certBytes}
	certPEM := pem.EncodeToMemory(&b)

	return cert, certPEM
}

func main() {
	GenRootCA()
}
