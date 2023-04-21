''' Handlers need to make sure they behave to avoid starvation. Since we are using epoll everything
    is running on one thread '''
import argparse
import select
import socket
import ssl
import time

def main():
    parser = argparse.ArgumentParser(description='Start an echo SSL Server')
    # python myServer 127.0.0.1 8080 --key server.key --cert server.crt --capath clients
    parser.add_argument('address', help='Address to bind to')
    parser.add_argument('port', type=int, help='Port to bind to')
    parser.add_argument('--key', help='Server key to use', required=True)
    parser.add_argument('--cert', help='Server certificate to use', required=True)
    parser.add_argument('--cafile', help='Client verification to use')

    args = parser.parse_args()

    def echo_handle(connection):
        print("handle")
        message = connection.recv_buf.decode()
        connection.recv_buf = b''
        print(message)
        capitalizedMessage = message.upper()
        return capitalizedMessage.encode()

    with EpollServer(args.address, args.port, args.cert, args.key, args.cafile, connection_timeout=1) as server:
        server.run_forever(echo_handle)

class EpollServer():
    def __init__(self, host, port, crt, key, cafile, connection_timeout=60000):
        self.context  = create_server_context(crt, key, cafile)
        self.pollmask = select.EPOLLIN | select.EPOLLHUP | select.EPOLLERR
        self.timeout  = connection_timeout
        self.addr = (host, port)
        self.start()

    def start(self):
        self.server = secure_server_socket(self.addr, self.context)
        #  self.server.setblocking(0) # Needed for edge-triggered vs level
        self.epoll  = select.epoll()
        self.epoll.register(self.server.fileno(), self.pollmask)
        self.connections = {}

    def run_forever(self, callback):
        while True:
            self.poll(callback)

    def poll(self, callback):
        poll_events = self.epoll.poll(timeout=self.timeout)
        poll_time   = time.time()
        for (fd, event) in poll_events:
            if event & (select.POLLHUP | select.POLLERR):
                self.connection_error(fd)
            elif fd == self.server.fileno():
                self.accept_connection()
            else:
                conn = self.connections[fd]
                prev_mask = conn.mask
                if event & select.EPOLLIN:
                    conn.handle_recv(callback)
                if event & select.EPOLLOUT:
                    conn.handle_send()

                if conn.mask & (select.EPOLLIN | select.EPOLLOUT) == 0:
                    self.remove_connection(fd)
                elif prev_mask != conn.mask:
                    self.epoll.modify(fd, conn.mask)

        # Check timeouts
        if self.timeout is not None:
            for fd in list(self.connections.keys()):
                last_event = self.connections[fd].last_event
                if last_event + self.timeout < poll_time:
                    self.remove_connection(fd)

    def connection_error(self, fd):
        if fd == self.server.fileno():
            self.restart()
        else:
            self.remove_connection(fd)

    def restart(self):
        self.close()
        self.start()

    def remove_connection(self, fd):
        print(f'Remove {fd}')
        self.connections[fd].socket.close()
        del self.connections[fd]
        #server.epoll.unregister(fd) # close of an fd should be removed automatically

    def accept_connection(self):
        client, addr = self.server.accept()
        fd = client.fileno()
        #  client.setblocking(0) # needed for edge triggered
        self.connections[fd] = Connection(client, addr, self.pollmask)
        self.epoll.register(fd, self.pollmask)

    def close(self):
        self.server.close()
        for fd in list(self.connections.keys()):
            self.remove_connection(fd)

    def __enter__(self):
        return self

    def __exit__(self, t, v, tr):
        self.close()

class Connection():
    def __init__(self, socket, addr, event_mask):
        self.socket = socket
        self.addr   = addr
        self.mask   = event_mask

        self.recv_buf, self.send_buf = b'', b''

        self.last_event = time.time()
        self.size = 4096

    def handle_recv(self, callback):
        self.last_event = time.time()
        try:
            recvd = self.socket.recv(self.size)
            if not recvd:
                self.mask &= ~select.EPOLLIN
            self.recv_buf += recvd
            to_send = callback(self)
            if to_send:
                self.send_buf += to_send
                self.mask |= select.EPOLLOUT
        except socket.error:
            self.mask &= ~select.EPOLLIN

    def handle_send(self):
        self.last_event = time.time()
        try:
            total_sent = self.socket.send(self.send_buf)
            if total_sent == 0 and len(self.send_buf) > 0:
                self.mask &= ~select.EPOLLOUT
            self.send_buf = self.send_buf[total_sent:]
        except socket.error:
            self.mask &= ~select.EPOLLOUT

    def __repr__(self):
        return f'{self.addr}\n\tIn: {self.recv_buf}\n\tOut: {self.send_buf}'

def secure_server_socket(address, context):
    server = socket.create_server(address)
    server = context.wrap_socket(server, server_side=True)
    return server

def secure_client_socket(address, context):
    client = socket.create_connection(address)
    client = context.wrap_socket(client, server_side=False, server_hostname=address[0])
    return client

DEFAULT_CONTEXT_OPTIONS = ssl.OP_SINGLE_ECDH_USE | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3| ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
def create_server_context(certfile, keyfile, cafile):
    context = create_ssl_context(ssl.Purpose.CLIENT_AUTH, certfile, keyfile, cafile)
    context.verify_mode = ssl.CERT_REQUIRED
    return context

def create_client_context(certfile, keyfile, cafile):
    return create_ssl_context(ssl.Purpose.SERVER_AUTH, certfile, keyfile, cafile)

def create_ssl_context(purpose, certfile, keyfile, cafile):
    context = ssl.create_default_context(purpose)
    if certfile is not None and keyfile is not None:
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    if cafile is not None:
        context.load_verify_locations(cafile=cafile)
    context.options |= DEFAULT_CONTEXT_OPTIONS
    return context

if __name__ == '__main__':
    main()
