# NetworkSecProj2

create certificate request:
openssl req -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr

create certificate:
openssl req -newkey rsa:2048 -nodes -keyout domain.key -x509 -days 365 -out domain.crt

create private key:
openssl genrsa -des3 -out domain.key 2048

create CA
openssl req -new -x509 -days 3650 -extensions v3_ca \ 
-keyout private/cakey.pem -out cacert.pem \
-config /etc/ssl/openssl.cnf
openssl s_server -accept 5555 -cert ccert.pem -certform PEM -key clientkey.pem -keyform PEM -CAfile rootCA.pem -state -debug
openssl req -new -nodes -keyout sprivate.pem -out srequest.csr -days 365
openssl x509 -req -days 500 -in srequest.csr -CA rootCA.pem -CAkey rootCA.key -out scert.pem
