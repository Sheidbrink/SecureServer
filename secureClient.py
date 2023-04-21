import socket
import ssl

client_key = 'client.key'
client_cert = 'client.crt'
server_cert = 'server.crt'

hostname = '127.0.0.1'
port = 8080

context = ssl.SSLContext(ssl.PROTOCOL_TLS, cafile=server_cert)
#  context = ssl.create_default_context()
context.load_cert_chain(certfile=client_cert, keyfile=client_key)
context.load_verify_locations(cafile=server_cert) # is this not redundant? it is if created with SSLContext above

context.verify_mode = ssl.CERT_REQUIRED

context.options |= ssl.OP_SINGLE_ECDH_USE
context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2

with socket.create_connection((hostname, port)) as sock:
    with context.wrap_socket(sock, server_side=False, server_hostname=hostname) as ssock:
        print(ssock.version())
        message = input("Please enter your message: ")
        ssock.send(message.encode())
        receives = ssock.recv(1024)
        print(receives)
