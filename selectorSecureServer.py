''' Handlers need to make sure they behave to avoid starvation.
    Since we are using selectors everything is running on one thread '''
import argparse
import selectors
import socket
import ssl
import time
import logging

DEFAULT_CONTEXT_OPTIONS = ssl.OP_SINGLE_ECDH_USE |\
                          ssl.OP_NO_SSLv2 |\
                          ssl.OP_NO_SSLv3 |\
                          ssl.OP_NO_TLSv1 |\
                          ssl.OP_NO_TLSv1_1 |\
                          ssl.OP_NO_TLSv1_2
log = logging.getLogger(__name__)


def main():
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(description='Start an echo SSL Server')
    # python myServer 127.0.0.1 8080 --key server.key --cert server.crt --capath clients
    parser.add_argument('address', help='Address to bind to')
    parser.add_argument('port', type=int, help='Port to bind to')
    parser.add_argument('--key', help='Server key to use', required=True)
    parser.add_argument('--cert', help='Server certificate to use', required=True)
    parser.add_argument('--cafile', help='Client verification to use')
    parser.add_argument('--timeout', help='Client connection timeout', type=int)

    args = parser.parse_args()

    def echo_handle(connection):
        log.debug('Handling %s' % connection)
        message = connection.recv_buf.decode()
        connection.recv_buf = b''
        log.debug('Received message: %s' % message)
        capitalizedMessage = message.upper()
        return capitalizedMessage.encode()

    with SelectorServer(args.address, args.port, args.cert, args.key, args.cafile, echo_handle, connection_timeout=args.timeout) as server:
        server.run_forever()

class SelectorServer():
    def __init__(self, host, port, crt, key, cafile, callback, connection_timeout=60000):
        log.debug('Starting server %s:%d' % (host, port))
        self.context  = create_server_context(crt, key, cafile)
        self.timeout  = connection_timeout
        self.addr     = (host, port)
        self.callback = callback
        self._start()

    def run_forever(self):
        while True:
            self.select()

    def select(self):
        select_events = self.selector.select(timeout=self.timeout)
        select_time   = time.time()
        for key, event in select_events:
            conn_info = key.data

            prev_mask = conn_info.mask
            if event & selectors.EVENT_READ:
                conn_info.handle_recv()
            if event & selectors.EVENT_WRITE:
                conn_info.handle_send()

            if conn_info.mask & (selectors.EVENT_READ | selectors.EVENT_WRITE) == 0:
                self.remove_connection(key)
            elif prev_mask != conn_info.mask:
                self.selector.modify(key.fileobj, conn_info.mask, key.data)

        # Check timeouts
        if self.timeout is not None:
            for key in list(self.connections):
                last_event = key.data.last_event
                if last_event + self.timeout < select_time:
                    self.remove_connection(key)

    def handle_recv(self):
        try:
            client, addr = self.server.accept()
            conn_info    = Connection(client, addr, selectors.EVENT_READ, self.callback)
            key          = self.selector.register(client, conn_info.mask, conn_info)

            self.connections.append(key)
            log.debug('Accepted %s' % conn_info)
        except ssl.SSLError as e:
            log.debug('Error accepting client: %s' % e)
        except ssl.SSLCertVerificationError:
            log.debug('Invalid client certificate trying to connect.')

    def _start(self):
        self.connections = []

        self.server = secure_server_socket(self.addr, self.context)
        self.mask   = selectors.EVENT_READ

        self.selector = selectors.DefaultSelector()
        self.selector.register(self.server, self.mask, self)

    def close(self):
        self.server.close()
        for key in list(self.connections): #list() will make a copy
            self.remove_connection(key)
        self.connections = []
        self.selector.close()

    def restart(self):
        self.close()
        self._start()

    def remove_connection(self, key):
        log.debug('Removing connection %s', key)
        self.selector.unregister(key.fileobj)
        key.fileobj.close()
        self.connections.remove(key)

    def __enter__(self):
        return self

    def __exit__(self, t, v, tr):
        self.close()

class Connection():
    def __init__(self, socket, addr, mask, callback):
        self.socket = socket
        self.addr = addr
        self.mask = mask
        self.callback = callback
        self.recv_buf, self.send_buf = b'', b''

        self.last_event = time.time()
        self.size = 4096

    def handle_recv(self):
        self.last_event = time.time()
        try:
            recvd = self.socket.recv(self.size)
            if not recvd:
                self.mask &= ~selectors.EVENT_READ
            self.recv_buf += recvd
            to_send = self.callback(self)
            if to_send:
                self.send_buf += to_send
                self.mask |= selectors.EVENT_WRITE
        except socket.error:
            self.mask &= ~selectors.EVENT_READ

    def handle_send(self):
        self.last_event = time.time()
        try:
            total_sent = self.socket.send(self.send_buf)
            self.send_buf = self.send_buf[total_sent:]
            if total_sent == 0 and len(self.send_buf) > 0:
                self.mask &= ~selectors.EVENT_WRITE
        except socket.error:
            self.mask &= ~selectors.EVENT_WRITE

    def __repr__(self):
        return f'{self.addr} {self.mask}\n\tIn: {self.recv_buf}\n\tOut: {self.send_buf}'

def secure_server_socket(address, context):
    ''' Create a TLS socket with given context '''
    server = socket.create_server(address)
    server = context.wrap_socket(server, server_side=True)
    return server

def secure_client_socket(address, context):
    ''' Create a client TLS socket with the given context '''
    client = socket.create_connection(address)
    client = context.wrap_socket(client, server_side=False, server_hostname=address[0])
    return client

def create_server_context(certfile, keyfile, cafile):
    ''' Create the ssl context for a server
    Parameters
    ----------
    certfile: PathLike
        server certificate
    keyfile: Pathlike
        server key
    cafile: Pathlike
        optional client certificates to verify
    '''
    context = create_ssl_context(ssl.Purpose.CLIENT_AUTH, certfile, keyfile, cafile)
    if cafile is not None:
        context.verify_mode = ssl.CERT_REQUIRED
    return context

def create_client_context(certfile, keyfile, cafile):
    ''' Create a ssl context for a client
    Parameters
    ----------
    cerfile: Pathlike
        Optional client certificate
    keyfile: Pathlike
        Optional client certificate
    cafile: Pathlike
        Server CAfile
    '''
    return create_ssl_context(ssl.Purpose.SERVER_AUTH, certfile, keyfile, cafile)

def create_ssl_context(purpose, certfile, keyfile, cafile):
    ''' Helper generic ssl context creation '''
    context = ssl.create_default_context(purpose)
    if certfile is not None and keyfile is not None:
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    if cafile is not None:
        context.load_verify_locations(cafile=cafile)
    context.options |= DEFAULT_CONTEXT_OPTIONS
    return context

if __name__ == '__main__':
    main()
