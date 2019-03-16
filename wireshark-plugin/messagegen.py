''' A dummy PCAP generator to exercise wireshark dissector.
'''
import sys
import argparse
import logging
import scapy
import socket
from gi.repository import GLib as glib
from scapy.layers.inet import IP, TCP
from tcpcl import contact, messages

class Worker(object):
    
    CHUNK_SIZE = 100 * 1024
    
    def __init__(self, args):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self.args = args
        self._on_stop = None
        
        self._listener = None
        self._active_sock = None
        self._passive_sock = None
        
        self.__active_tx_buf = bytearray()
        self.__passive_tx_buf = bytearray()
    
    def _chunked_tx(self, sock, cond, *args):
        frombuf = args[0]
        
        sent_size = 0
        while len(frombuf) > 0:
            data = frombuf[:self.CHUNK_SIZE]
            self.__logger.debug('Sending chunk %d/%d octets', len(data), len(frombuf))
            try:
                tx_size = sock.send(data)
                self.__logger.debug('Sent %d chunk %d octets', sock.fileno(), tx_size)
            except socket.error as err:
                self.__logger.warning('Failed to send chunk: %s', err)
                tx_size = None
            if tx_size:
                frombuf[:] = frombuf[tx_size:]
                sent_size += tx_size

        if len(self.__passive_tx_buf) + len(self.__active_tx_buf) == 0:
            glib.timeout_add(100, lambda: self.stop())

        if sent_size == 0:
            return False
        return True
    
    def _chunked_rx(self, sock, cond, *args):
        tobuf = args[0]
        
        try:
            data = sock.recv(self.CHUNK_SIZE)
            self.__logger.debug('Received %d chunk %d octets', sock.fileno(), len(data))
        except socket.error as err:
            self.__logger.warning('Failed to recv chunk: %s', err)
            data = None
        
        if not data:
            # Connection closed
            return False

        if tobuf is not None:
            tobuf += data
        
        return True
    
    def _accept(self, bindsock, *args, **kwargs):
        ''' Callback to handle incoming connections.
        
        :return: True to continue listening.
        '''
        sock, fromaddr = bindsock.accept()
        self.__logger.info('Connecting')
        self._passive_sock = sock
        
        glib.io_add_watch(self._passive_sock, glib.IO_OUT, self._chunked_tx, self.__passive_tx_buf)
        glib.io_add_watch(self._passive_sock, glib.IO_IN, self._chunked_rx, None)
        # Prime the TX
        self._chunked_tx(sock, None, self.__passive_tx_buf)
        
        return True

    def set_on_stop(self, func):
        ''' Set a callback to be run when this agent is stopped.
        
        :param func: The callback, which takes no arguments.
        '''
        self._on_stop = func
    
    def start(self):
        sockaddr = ('localhost', 4556)
        
        sock = socket.socket(socket.AF_INET)
        sock.bind(sockaddr)
        sock.listen(1)
        self._listener = sock
        glib.io_add_watch(self._listener, glib.IO_IN, self._accept)
        
        sock = socket.socket(socket.AF_INET)
        sock.connect(sockaddr)
        self._active_sock = sock
        glib.io_add_watch(self._active_sock, glib.IO_OUT, self._chunked_tx, self.__active_tx_buf)
        glib.io_add_watch(self._active_sock, glib.IO_IN, self._chunked_rx, None)
        
        self.__active_tx_buf += bytes(contact.Head()/contact.ContactV4())
        self.__active_tx_buf += bytes(messages.MessageHead()/messages.SessionInit(
            segment_mru=100,
            transfer_mru=1000,
        ))
        self.__active_tx_buf += bytes(messages.MessageHead()/messages.RejectMsg(
            reason=messages.RejectMsg.Reason.UNEXPECTED
        ))
        self.__active_tx_buf += bytes(messages.MessageHead()/messages.SessionTerm(
            reason=messages.SessionTerm.Reason.RESOURCE_EXHAUSTION
        ))
        self.__active_tx_buf += bytes(messages.MessageHead()/messages.TransferAck(
            transfer_id=30,
            length=24,
        ))
        self.__active_tx_buf += bytes(messages.MessageHead()/messages.TransferRefuse(
            transfer_id=40,
            reason=messages.TransferRefuse.Reason.RESOURCES,
        ))
        self.__active_tx_buf += bytes(messages.MessageHead()/messages.TransferSegment(
            flags=messages.TransferSegment.Flag.START | messages.TransferSegment.Flag.END,
            transfer_id=5,
            data=b'hithere'
        ))
        
        self.__passive_tx_buf += bytes(contact.Head()/contact.ContactV4())
        self.__passive_tx_buf += bytes(messages.MessageHead()/messages.TransferRefuse(
            transfer_id=5,
            reason=messages.TransferRefuse.Reason.RESOURCES,
        ))
        self.__passive_tx_buf += bytes(messages.MessageHead()/messages.TransferAck(
            transfer_id=5,
            length=10,
        ))
        
        # Prime the TX
        self._chunked_tx(sock, None, self.__active_tx_buf)

    def stop(self):
        # Order of shutdown is significant, listener must be last
        for sock in (self._active_sock, self._passive_sock, self._listener):
            if sock.fileno() < 0:
                continue
            self.__logger.debug('Shutting down FD:%d', sock.fileno())
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except socket.error as err:
                self.__logger.error('Socket shutdown error: %s', err)
            sock.close()

        if self._on_stop:
            self._on_stop()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    args = parser.parse_args()
    
    logging.basicConfig(level=args.log_level.upper())
    logging.debug('command args: %s', args)
    
    worker = Worker(args)
    worker.start()
    
    eloop = glib.MainLoop()
    worker.set_on_stop(lambda: eloop.quit())
    try:
        eloop.run()
    except KeyboardInterrupt:
        pass
    worker.stop()

    #with scapy.utils.PcapWriter(args.outfile) as fdesc:

if __name__ == '__main__':
    sys.exit(main())
