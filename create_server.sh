openssl req -new -newkey rsa:3072 -days 365 -nodes -x509 -keyout server.key -out server.crt -addext "subjectAltName = IP:127.0.0.1"
# openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -x509 -nodes -days 365 -out server.crt -keyout server.key
