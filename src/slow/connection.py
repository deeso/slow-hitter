import json
import socket
from kombu import Connection as _KombuConnection


class Message(object):

    def __init__(self, data):
        self._data = data

    @property
    def payload(self):
        return self._data

    def ack(self):
        pass


class Connection(object):

    def __init__(self):
        pass

    @property
    def socket(self):
        raise Exception("Not implemented")

    def send_message(self, msg):
        raise Exception("Not implemented")

    def recv_message(self, msg):
        # returns a Message
        raise Exception("Not implemented")

    @classmethod
    def create_connection(cls, uri, queue='default'):
        if uri.strip().find('udp://') == 0:
            return UdpConnection(uri.strip())
        elif uri.strip().find('tcp://') == 0:
            return TcpConnection(uri.strip())
        elif uri.strip().find('aqmp://') == 0 or\
             uri.strip().find('redis://') == 0:
            return KombuConnection(uri.strip(), queue=queue)
        raise Exception("Unable to handle URI type: %s" % uri)


class UdpConnection(Connection):

    def __init__(self, uri):
        self.host = uri.split('udp://')[1].split(':')[0]
        self.port = int(uri.split(':')[0])
        self.server = (self.host, self.port)
        self._socket = None

    @property
    def socket(self):
        if self._socket is None:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._socket

    def send_message(self, msg):
        try:
            l = self.socket.sendto(msg, self.server)
            return l
        except:
            raise


class TcpConnection(Connection):

    def __init__(self, uri):
        self.host = uri.split('tcp://')[1].split(':')[0]
        self.port = int(uri.split(':')[0])
        self.server = (self.host, self.port)
        self._socket = None

    @property
    def socket(self):
        if self._socket is None:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect(self.server)
        return self._socket

    def send_message(self, msg):
        try:
            l = self.socket.send(msg)
            return l
        except:
            raise


class KombuConnection(Connection):

    def __init__(self, uri, queue='default'):
        self.uri = uri
        self._socket = None
        self.queue_name = queue
        self._queue = None

    @property
    def socket(self):
        if self._socket is None:
            self._socket = _KombuConnection(self.uri)
        return self._socket

    @property
    def connection(self):
        return self.socket

    @property
    def queue(self):
        if self._queue is None:
            self._queue = self.socket.Queue(self.queue_name)
        return self._queue

    def send_message(self, msg):
        try:
            self.queue.put(json.dumps(msg))
            self.queue.q.close()
        except:
            raise

    def read_messages(self, callback=None, cnt=1):
        msgs = []
        read_all = False
        if cnt < 1:
            read_all = True

        while cnt > 0 or read_all:
            cnt += -1
            try:
                message = self.queue.get(block=False)
                data = message.payload
                msgs.append(data)
                if callback is not None:
                    callback(data)
                message.ack()
            except Queue.Empty:
                break
        return msgs

    def read_message(self, callback=None):
        return self.read_messages(cnt=1, callback=callback)
