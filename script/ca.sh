#!/bin/bash

caDir="rkccCA"
caCnf="caconfig.cnf"
caPEMPass="11001"

CUR_BASE_DIR=${PWD}
rm -rf "${caDir}"
mkdir ${caDir} && mkdir -p ${caDir}/signedcerts && mkdir ${caDir}/private && cd "${caDir}" || exit
echo '01' >serial && touch index.txt

cat <<EOF >${caCnf}
# My sample caconfig.cnf file.
#
# Default configuration to use when one is not provided on the command line.
#
[ ca ]
default_ca = local_ca
#
#
# Default location of directories and files needed to generate certificates.
#
[ local_ca ]
dir = ${CUR_BASE_DIR}
certificate = ${CUR_BASE_DIR}/${caDir}/ca.crt
database = ${CUR_BASE_DIR}/${caDir}/index.txt
new_certs_dir = ${CUR_BASE_DIR}/${caDir}/signedcerts
private_key = ${CUR_BASE_DIR}/${caDir}/private/ca.key
serial = ${CUR_BASE_DIR}/${caDir}/serial
#
#
# Default expiration and encryption policies for certificates
#
default_crl_days = 365
default_days = 1825
# sha1 is no longer recommended, we will be using sha256
default_md = sha256
#
policy = local_ca_policy
x509_extensions = local_ca_extensions

#
#
# Copy extensions specified in the certificate request
#
copy_extensions = copy
#
#
# Default policy to use when generating server certificates.
# The following fields must be defined in the server certificate.
#
# DO NOT CHANGE "supplied" BELOW TO ANYTHING ELSE.
# It is the correct content.
#
[ local_ca_policy ]
commonName = supplied
stateOrProvinceName = supplied
countryName = supplied
emailAddress = supplied
organizationName = supplied
organizationalUnitName = supplied
#
#
# x509 extensions to use when generating server certificates
#
[ local_ca_extensions ]
basicConstraints = CA:false
#
#
# The default root certificate generation policy
#
[ req ]
default_bits = 2048
default_keyfile = ${CUR_BASE_DIR}/${caDir}/private/ca.key
#
# sha1 is no longer recommended, we will be using sha256
default_md = sha256
#
prompt = no
distinguished_name = root_ca_distinguished_name
x509_extensions = root_ca_extensions
#
#
# Root Certificate Authority distinguished name
#
# DO CHANGE THE CONTENT OF THESE FIELDS TO MATCH
# YOUR OWN SETTINGS!
#
[ root_ca_distinguished_name ]
commonName = Cloudchain Root Certificate Authority
stateOrProvinceName = NSW
countryName = AU
emailAddress = nobody@querycap.com
organizationName = Cloudchain
organizationalUnitName = CA Unit
#
[ root_ca_extensions ]
basicConstraints = CA:true
EOF

/usr/bin/expect <<EOD
spawn openssl req -x509 -newkey rsa:2048 -out ca.crt -outform PEM -days 3650 -config ${CUR_BASE_DIR}/${caDir}/${caCnf}
expect {
"Enter PEM pass phrase:" { send "$caPEMPass\n"; exp_continue}
"Verifying - Enter PEM pass phrase:" { send "$caPEMPass\n" }
}
EOD

echo "Successfully generated:"
echo "CA cert: ${CUR_BASE_DIR}/${caDir}/ca.crt"
echo "CA key: ${CUR_BASE_DIR}/${caDir}/private/ca.key"