#!/bin/bash

caDir="rkccCA"
caCnf="caconfig.cnf"
localCnf="local.cnf"
caPEMPass="11001"
pemPass="11002"
orgID="1247351936810991625"
orgName="rockontrol online org1"
orgEmail="nobody@example.com"
DNS="cloudchain.cc-dongchang1.rockontrol.com"

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