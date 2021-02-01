package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"text/template"
)

var doc = `
#!/bin/bash

caDir="{{.CADir}}"
caCnf="{{.CACfg}}"
localCnf="{{.LocalCfg}}"
caPEMPass="{{.CAPass}}"
pemPass="{{.LocalPass}}"
orgID="{{.OrgID}}"
orgName="{{.OrgName}}"
orgEmail="{{.OrgEmail}}"
DNS="{{.DNS}}"

CUR_BASE_DIR=${PWD}
cd "${caDir}" || exit
cat <<EOF >${localCnf}
#
# localhost.cnf
#

[ req ]
prompt = no
distinguished_name = server_distinguished_name
req_extensions = v3_req

[ server_distinguished_name ]
commonName = $orgName
stateOrProvinceName = NSW
countryName = AU
emailAddress = $orgEmail
organizationName = $orgName
organizationalUnitName = $orgID

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, keyCertSign, cRLSign
extendedKeyUsage = clientAuth, serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.0 = ${DNS}
EOF

# 生成请求1
/usr/bin/expect <<EOD
spawn openssl req -newkey rsa:2048 -keyout $orgID.pem -keyform PEM -out $orgID.csr -outform PEM -config ${CUR_BASE_DIR}/${caDir}/${localCnf}
expect {
"Enter PEM pass phrase:" { send "$pemPass\n"; exp_continue}
"Verifying - Enter PEM pass phrase:" { send "$pemPass\n" }
}
spawn openssl rsa -in $orgID.pem -out server_key1.pem
expect {
".pem:" { send "$pemPass\n"}
}
EOD

# 签证书1和key1
/usr/bin/expect <<EOD
spawn openssl ca -in $orgID.csr -out $orgID.crt -config ${CUR_BASE_DIR}/${caDir}/${caCnf}
expect {
"Enter pass phrase for ${CUR_BASE_DIR}/${caDir}/private/ca.key:" { send "$caPEMPass\n"; exp_continue}
"n]:" { send "y\n"; exp_continue}
"n]" { send "y\n"; exp_continue}
}
spawn openssl pkcs8 -topk8 -inform pem -in $orgID.pem -outform pem -nocrypt -out $orgID.key
expect {
".pem:" { send "$pemPass\n"; exp_continue}
}
EOD

echo "Successfully generated:"

echo "cert: ${CUR_BASE_DIR}/${caDir}/"$orgID".crt"
echo "key: ${CUR_BASE_DIR}/${caDir}/"$orgID".key"
`
var (
	caDir     string
	caCfg     string
	caPass    string
	localCfg  string
	localPass string
	dns       string
	orgID     string
	orgName   string
	orgEmail  string
	globArg   Arg
	shell     string
)

func init() {
	flag.StringVar(&caDir, "caDir", "rkccCA", "ca output directory")
	flag.StringVar(&caCfg, "caCfg", "caconfig.cnf", "ca config file")
	flag.StringVar(&caPass, "caPass", "11001", "ca pem pass")
	flag.StringVar(&localCfg, "localCfg", "local.cnf", "local config file")
	flag.StringVar(&localPass, "localPass", "11002", "pem pass")
	flag.StringVar(&dns, "dns", "srv-peer.cloudchain", "x509 dns")
	flag.StringVar(&orgID, "orgID", "1042993609097351173", "organization ID")
	flag.StringVar(&orgName, "orgName", "rockcontrol test org1", "organization name")
	flag.StringVar(&orgEmail, "orgEmail", "nobody@example.com", "organization email address")
	flag.StringVar(&shell, "s", "/bin/sh", "shell path")
	flag.Parse()

	globArg.CADir = caDir
	globArg.CACfg = caCfg
	globArg.CAPass = caPass
	globArg.LocalCfg = localCfg
	globArg.LocalPass = localPass
	globArg.DNS = dns
	globArg.OrgID = orgID
	globArg.OrgName = orgName
	globArg.OrgEmail = orgEmail
}

type Arg struct {
	CADir     string
	CACfg     string
	CAPass    string
	LocalCfg  string
	LocalPass string
	DNS       string
	OrgID     string
	OrgName   string
	OrgEmail  string
}

func main() {
	t := template.New("")
	t, err := t.Parse(doc)
	if err != nil {
		log.Fatal(err)
	}

	output := fmt.Sprintf("%s.sh", orgID)
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0744)
	if err != nil {
		log.Fatal(err)
	}

	err = t.Execute(f, globArg)
	if err != nil {
		log.Fatal(err)
	}
	f.Close()

	cmd := exec.Command(shell, output)
	rc, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	go cmd.Start()
	var buf [1024]byte
	for {
		n, err := rc.Read(buf[:])
		if err != nil {
			if err == io.EOF {
				rc.Close()
				break
			}
			log.Fatal(err)
		}
		fmt.Printf("%s", string(buf[:n]))
	}
}
