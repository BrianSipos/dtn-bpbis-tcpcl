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
        
        self.__active_tx_buf = bytes()
    
    def _active_tx(self, sock, *args, **kwargs):
        sent_size = 0
        while len(self.__active_tx_buf) > 0:
            data = self.__active_tx_buf[:self.CHUNK_SIZE]
            self.__logger.debug('Sending message %d/%d octets', len(data), len(self.__active_tx_buf))
            try:
                tx_size = sock.send(data)
                self.__logger.debug('Sent %d octets', tx_size)
            except socket.error as err:
                self.__logger.warning('Failed to send chunk: %s', err)
                tx_size = None
            if tx_size:
                self.__active_tx_buf = self.__active_tx_buf[tx_size:]
                sent_size += tx_size

        if sent_size == 0:
            self.stop()
            return False
        return True
    
    def _passive_rx(self, sock, *args, **kwargs):
        try:
            data = sock.recv(self.CHUNK_SIZE)
        except socket.error as err:
            self.__logger.warning('Failed to recv chunk: %s', err)
            data = None
        if not data:
            # Connection closed
            self.stop()
            return False

        return True
    
    def _accept(self, bindsock, *args, **kwargs):
        ''' Callback to handle incoming connections.
        
        :return: True to continue listening.
        '''
        newsock, fromaddr = bindsock.accept()
        self.__logger.info('Connecting')
        self._passive_sock = newsock
        glib.io_add_watch(self._passive_sock, glib.IO_IN, self._passive_rx)
        
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
        glib.io_add_watch(self._active_sock, glib.IO_OUT, self._active_tx)
        
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

    def stop(self):
        # Order of shutdown is significant, listener must be last
        for sock in (self._active_sock, self._passive_sock, self._listener):
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
