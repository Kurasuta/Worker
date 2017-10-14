import time
import socket


class Graphite(object):
    def __init__(self, server='localhost', port=2003):
        self.server = server
        self.port = port

    def collect(self, name, value, timestamp=None):
        if timestamp is None:
            timestamp = int(time.time())  # use now
        sock = socket.socket()
        sock.connect((self.server, self.port))
        sock.send('%s %f %d\n' % (name, value, timestamp))
        sock.close()


if __name__ == '__main__':
    Graphite().collect('metric.name', 42)
