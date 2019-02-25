'''
Implementation of a symmetric TCPCL agent.
'''

import sys
import logging
import argparse
import socket
import ssl
from gi.repository import GLib as glib
import dbus.bus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
import StringIO
import os
import math
import datetime
from tcpcl import formats, contact, messages, xferextend

def combine_flags(names):
    if len(names):
        return '+'.join(names)
    else:
        return 0

class Config(object):
    ''' Agent configuration.
    
    .. py:attribute:: eid
        The EID of this node.
    .. py:attribute:: bus_conn
        An optional D-Bus connection object to register handlers on.
    '''
    def __init__(self):
        self.bus_conn = None
        self.ssl_ctx = None
        self.tls_require = None
        self.eid = ''
        self.keepalive_time = 0
        self.idle_time = 0
        #: Maximum size of transmit segments in octets
        self.segment_size = 10240

class Connection(object):
    ''' Optionally secured socket connection.
    This handles octet-level buffering and queuing.
    
    :param sock: The unsecured socket to wrap.
    :type sock: :py:class:`socket.socket`
    :param as_passive: True if this is the passive side of the connection.
    :type as_passive: bool
    :param peer_name: The name of the socket peer.
    :type peer_name: str
    '''
    def __init__(self, sock, as_passive, peer_name):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self._on_close = None
        self._as_passive = as_passive
        self._peer_name = peer_name
        
        #: Transmit buffer
        self.__tx_buf = ''
        
        #: The raw socket
        self.__s_notls = None
        #: Optionally secured socket
        self.__s_tls = None
        
        #: listener for __s_notls socket
        self.__avail_rx_notls_id = None
        self.__avail_tx_notls_id = None
        self.__avail_tx_notls_pend = None
        #: optional listener for __s_tls socket
        self.__avail_rx_tls_id = None
        self.__avail_tx_tls_id = None
        self.__avail_tx_tls_pend = None
        
        self._replace_socket(sock)
    
    def is_secure(self):
        ''' Determine if TLS is established.
        
        :return: True if operating with TLS.
        '''
        return (self.__s_tls is not None)
    
    def __unlisten_notls(self):
        if self.__avail_rx_notls_id is not None:
            glib.source_remove(self.__avail_rx_notls_id)
            self.__avail_rx_notls_id = None
        if self.__avail_tx_notls_id is not None:
            glib.source_remove(self.__avail_tx_notls_id)
            self.__avail_tx_notls_id = None
    
    def __unlisten_tls(self):
        if self.__avail_rx_tls_id is not None:
            glib.source_remove(self.__avail_rx_tls_id)
            self.__avail_rx_tls_id = None
        if self.__avail_tx_tls_id is not None:
            glib.source_remove(self.__avail_tx_tls_id)
            self.__avail_tx_tls_id = None
    
    def _replace_socket(self, sock):
        ''' Replace the socket used by this object.
        Any current socket is left open.
        
        :param sock: The new socket.
        :type sock: :py:class:`socket.socket`
        :return: The old socket.
        '''
        old = self.__s_notls
        self.__unlisten_notls()
        
        self.__s_notls = sock
        if self.__s_notls is not None:
            self.__s_notls.setblocking(0)
            self.__avail_rx_notls_id = glib.io_add_watch(self.__s_notls, glib.IO_IN, self._avail_rx_notls)
        
        return old
    
    def set_on_close(self, func):
        ''' Set a callback to be run when this connection is closed.
        
        :param func: The callback, which takes no arguments.
        '''
        self._on_close = func
    
    def close(self):
        ''' Close the entire connection cleanly.
        '''
        if not self.__s_notls:
            return
        self.__logger.info('Closing connection')
        
        self.__unlisten_tls()
        self.__unlisten_notls()
        
        # Best effort to close active socket
        for sock in (self.__s_tls, self.__s_notls):
            if sock is None:
                continue
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except socket.error as err:
                self.__logger.error('Socket shutdown error: %s', err)
            sock.close()
        
        self.__s_notls = None
        self.__s_tls = None
        
        if self._on_close:
            self._on_close()
    
    def secure(self, ssl_ctx):
        ''' Add a TLS connection layer (if not present).
        
        :param ssl_ctx: The context to use for security.
        :type ssl_ctx: :py:class:`ssl.SSLContext`
        :raise ssl.SSLError: If the negotiation fails.
        '''
        if self.__s_tls:
            return
        
        # Pass socket control to TLS
        self.__unlisten_notls()
        self.__s_notls.setblocking(1)
        
        if self._as_passive:
            s_tls = ssl_ctx.wrap_socket(self.__s_notls,
                                              server_side=True,
                                              do_handshake_on_connect=False)
        else:
            s_tls = ssl_ctx.wrap_socket(self.__s_notls,
                                              server_hostname=self._peer_name,
                                              do_handshake_on_connect=False)
        
        self.__logger.debug('Negotiating TLS...')
        try:
            s_tls.do_handshake()
        except ssl.SSLError as err:
            self.__logger.debug('TLS failed: %s', err)
            # leave non-TLS socket in place
            #self.__s_tls = None
            self.unsecure()
            raise
        
        self.__s_tls = s_tls
        self.__logger.info('TLS secured with %s', self.__s_tls.cipher())
        
        self.__s_tls.setblocking(0)
        self.__avail_rx_tls_id = glib.io_add_watch(self.__s_tls, glib.IO_IN, self._avail_rx_tls)
    
    def unsecure(self):
        ''' Remove any TLS connection layer (if present).
        '''
        if not self.__s_tls:
            return
        
        self.__logger.debug('Unsecuring TLS...')
        self.__unlisten_tls()
        
        # Keep the unsecured socket
        new_sock = self.__s_tls.unwrap()
        self.__s_tls = None
        self._replace_socket(new_sock)
    
    def _conn_name(self):
        ''' A name for the connection type. '''
        if self.is_secure():
            return 'secure'
        else:
            return 'plain'
    
    #: Size of data stream chunks
    CHUNK_SIZE = 10240
    #: True to log actual hex-encoded data
    DO_DEBUG_DATA = False
    
    def _avail_rx_notls(self, *args, **kwargs):
        ''' Callback for new :py:obj:`__s_notls` RX data. '''
        if self.__s_tls is not None:
            return True
        
        return self._rx_proxy(self.__s_notls)
    
    def _avail_rx_tls(self, *args, **kwargs):
        ''' Callback for new :py:obj:`__s_tls` RX data. '''
        if self.__s_tls is None:
            return True
        
        return self._rx_proxy(self.__s_tls)
    
    def _rx_proxy(self, sock):
        self.__logger.debug('RX proxy')
        
        data = sock.recv(self.CHUNK_SIZE)
        if len(data) == 0:
            # Connection closed
            self.close()
            return False
        
        self.__logger.debug('Received %d octets (%s)', len(data), self._conn_name())
        self.recv_raw(data)
        return True
    
    def recv_raw(self, data):
        ''' Handler for a received block of data.
        Derived classes must overload this method to handle RX data.
        
        :param data: The received data.
        :type data: str
        '''
        pass
    
    def _avail_tx_notls(self, *args, **kwargs):
        ''' Callback for new :py:obj:`__s_notls` TX data. '''
        self.__avail_tx_notls_pend = None
        if self.__s_tls is not None or self.__s_notls is None:
            return False
        
        cont = self._tx_proxy(self.__s_notls)
        if not cont:
            self.__avail_tx_notls_id = None
        return cont
    
    def _avail_tx_tls(self, *args, **kwargs):
        ''' Callback for new :py:obj:`__s_tls` TX data. '''
        self.__avail_tx_tls_pend = None
        if self.__s_tls is None:
            return False
        
        cont = self._tx_proxy(self.__s_tls)
        if not cont:
            self.__avail_tx_tls_id = None
        return cont
    
    def _tx_proxy(self, sock):
        ''' Process up to a single CHUNK_SIZE outgoing block.
        '''
        # Pull messages into buffer
        if len(self.__tx_buf) < self.CHUNK_SIZE:
            data = self.send_raw(self.CHUNK_SIZE)
            self.__tx_buf += data
            up_empty = (len(data) == 0)
        else:
            up_empty = False
    
        # Flush chunks from the buffer
        sent_size = 0
        if len(self.__tx_buf) > 0:
            data = self.__tx_buf[:self.CHUNK_SIZE]
            self.__logger.debug('Sending message %d/%d octets (%s)', len(data), len(self.__tx_buf), self._conn_name())
            tx_size = sock.send(data)
            self.__logger.debug('Sent %d octets', tx_size)
            self.__tx_buf = self.__tx_buf[tx_size:]
            sent_size += tx_size
            
        buf_empty = (len(self.__tx_buf) == 0)
        if sent_size:
            self.__logger.debug('TX %d octets, remain %d octets (msg empty %s)', sent_size, len(self.__tx_buf), up_empty)
        cont = (not buf_empty or not up_empty)
        return cont
    
    def send_ready(self):
        ''' Called to indicate that :py:meth:`send_raw` will return non-empty.
        This will attempt immediate transmit of chunks if available, and
        queue the rest for later.
        '''
        if self.__s_tls:
            if self.__avail_tx_tls_id is None:
                self.__avail_tx_tls_id = glib.io_add_watch(self.__s_tls, glib.IO_OUT, self._avail_tx_tls)
            if self.__avail_tx_tls_pend is None:
                self.__avail_tx_tls_pend = glib.idle_add(self._avail_tx_tls)
        
        else:
            if self.__avail_tx_notls_id is None:
                self.__avail_tx_notls_id = glib.io_add_watch(self.__s_notls, glib.IO_OUT, self._avail_tx_notls)
            if self.__avail_tx_notls_pend is None:
                self.__avail_tx_notls_pend = glib.idle_add(self._avail_tx_notls)
    
    def send_raw(self, size):
        ''' Obtain a block of data to send.
        Derived classes must overload this method to return TX data.
        
        :param size: The maximum size to obtain.
        :type size: int
        :return: The to-be-transmitted data.
        :rtype: str
        '''
        return ''

class RejectError(Exception):
    ''' Allow recv_ handlers to reject the message.
    
    :param reason: The rejection reason.
    :type reason: int
    '''
    def __init__(self, reason=None):
        Exception.__init__(self, 'rejected')
        self.reason = reason

class Messenger(Connection):
    ''' Messaging layer of TCPCL.
    This handles message-level buffering and queuing.
    Messages are variable-length individually.
    
    :param config: The messenger configuration struct.
    :type config: :py:class:`Config`
    :param sock: The (unsecured) connection socket to operate on.
    :type sock: :py:class:`socket.socket`
    '''
    def __init__(self, config, sock, fromaddr=None, toaddr=None):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self._config = config
        
        # agent-configured parmeters
        self._do_send_ack_inter = None
        self._ack_inter_time_min = datetime.timedelta(milliseconds=100)
        self._do_send_ack_final = None
        # negotiated parameters
        self._keepalive_time = 0
        self._idle_time = 0
        self._send_segment_size = None
        # agent timers
        self._ack_inter_time_last = None
        self._keepalive_timer_id = None
        self._idle_timer_id = None
        
        # Negotiation inputs and states
        self._conhead_peer = None
        self._conhead_this = None
        self._in_conn = False # Set after contact negotiation
        self._sessinit_peer = None
        self._sessinit_this = None
        self._in_sess = False # Set after SESS_INIT negotiation
        
        # Assume socket is ready
        self._is_open = True
        # In closing state
        self._wait_sess_term = False
        
        self._from = fromaddr
        self._to = toaddr
        #: Receive pre-message data buffer
        self.__rx_buf = ''
        #: Transmit post-message data buffer
        self.__tx_buf = ''
        
        # now set up connection
        if fromaddr:
            as_passive = True
            peer_name = fromaddr[0]
        else:
            as_passive = False
            peer_name = toaddr[0]
        Connection.__init__(self, sock, as_passive, peer_name)
    
    def is_server(self):
        return (self._from is not None)
    
    def recv_buffer_used(self):
        ''' Get the number of octets waiting in the receive buffer.
        
        :return: The buffer use (octets).
        :rtype: int.
        '''
        return len(self.__rx_buf)
    
    def send_buffer_used(self):
        ''' Get the number of octets waiting in the transmit buffer.
        
        :return: The buffer use (octets).
        :rtype: int.
        '''
        return len(self.__tx_buf)
    
    def send_buffer_decreased(self, buf_use):
        ''' A handler function to be used when message buffer data is
        transmitted.
        
        :param buf_use: The current buffer use (octets).
        :type buf_use: int
        '''
        pass
    
    def close(self):
        self._idle_stop()
        self._keepalive_stop()
        super(Messenger, self).close()
    
    def _keepalive_stop(self):
        ''' Inhibit keepalive timer. '''
        if self._keepalive_timer_id is not None:
            glib.source_remove(self._keepalive_timer_id)
            self._keepalive_timer_id = None
    
    def _keepalive_reset(self):
        ''' Reset keepalive timer upon TX. '''
        self._keepalive_stop()
        if self._keepalive_time > 0:
            self._keepalive_timer_id = glib.timeout_add(int(self._keepalive_time * 1e3), self._keepalive_timeout)
        
    def _keepalive_timeout(self):
        ''' Handle TX keepalive. '''
        self.__logger.debug('Keepalive time')
        self.send_message(messages.MessageHead()/messages.Keepalive())
    
    def _idle_stop(self):
        ''' Inhibit the idle timer. '''
        if self._idle_timer_id is not None:
            glib.source_remove(self._idle_timer_id)
            self._idle_timer_id = None
    
    def _idle_reset(self):
        ''' Reset the idle timer upon TX or RX. '''
        self._idle_stop()
        if self._idle_time > 0:
            self._idle_timer_id = glib.timeout_add(int(self._idle_time * 1e3), self._idle_timeout)
    
    def _idle_timeout(self):
        ''' Handle an idle timer timeout. '''
        self._idle_stop()
        self.__logger.debug('Idle time reached')
        self.do_sess_term(messages.SessionTerm.REASON_IDLE)
        return False
    
    def recv_raw(self, data):
        ''' Attempt to extract a message from the current read buffer.
        '''
        self._idle_reset()
        # always append
        self.__rx_buf += data
        self.__logger.debug('RX buffer size %d octets', len(self.__rx_buf))
        
        # Handle as many messages as are present
        while len(self.__rx_buf):
            if self._in_conn:
                msgcls = messages.MessageHead
            else:
                msgcls = contact.Head
            
            # Probe for full message (by reading back encoded data)
            try:
                pkt = msgcls(self.__rx_buf)
                pkt_data = str(pkt)
            except formats.VerifyError as err:
                self.__logger.debug('Decoded partial packet: %s', err)
                return
            except Exception as err:
                self.__logger.error('Failed to decode packet: %s', err)
                return
            if self.DO_DEBUG_DATA:
                self.__logger.debug('RX packet data: %s', pkt_data.encode('hex'))
            self.__logger.debug('Matched message %d octets', len(pkt_data))
            
            # Keep final padding as future data
            self.__rx_buf = self.__rx_buf[len(pkt_data):]
            self.__logger.debug('RX remain %d octets', len(self.__rx_buf))
            
            self.recv_message(pkt)
    
    def recv_message(self, pkt):
        ''' Handle a received full message (or contact header).
        
        :param pkt: The message packet received.
        '''
        self.__logger.info('RX: %s', repr(pkt))
        
        if isinstance(pkt, contact.Head):
            if pkt.magic != contact.MAGIC_HEAD:
                raise ValueError('Contact header with bad magic: {0}'.format(pkt.magic.encode('hex')))
            if pkt.version != 4:
                raise ValueError('Contact header with bad version: {0}'.format(pkt.version))
            
            if self._as_passive:
                # After initial validation send reply
                self._conhead_this = self.send_contact_header().payload
            
            self._conhead_peer = pkt.payload
            self.merge_contact_params()
            self._in_conn = True
            
            # Check policy before attempt
            if self._config.tls_require is not None:
                if self._tls_attempt != self._config.tls_require:
                    self.__logger.error('TLS parameter violated policy')
                    self.close()
                    return
            
            # Boths sides immediately try TLS, Client initiates handshake
            if self._tls_attempt:
                # flush the buffers ahead of TLS
                while self.__tx_buf:
                    self._avail_tx_notls()
                
                # Either case, TLS handshake begins
                try:
                    self.secure(self._config.ssl_ctx)
                except ssl.SSLError as err:
                    pass
            
            # Check policy after attempt
            if self._config.tls_require is not None:
                if self.is_secure() != self._config.tls_require:
                    self.__logger.error('TLS result violated policy')
                    self.close()
                    return
            
            # Contact negotiation is completed, begin session negotiation
            if not self._as_passive:
                # Passive side listens first
                self._sessinit_this = self.send_sess_init().payload
        
        else:
            # Some payloads are empty and scapy will not construct them
            msgcls = pkt.guess_payload_class('')
            
            try: # Allow rejection from any of these via RejectError
                if msgcls == messages.SessionInit:
                    if self._as_passive:
                        # After initial validation send reply
                        self._sessinit_this = self.send_sess_init().payload
                    
                    self._sessinit_peer = pkt.payload
                    self.merge_session_params()
                    self._in_sess = True
                
                elif msgcls == messages.SessionTerm:
                    # Send a reply (if not the initiator)
                    if not self._wait_sess_term:
                        self.do_sess_term()
                    
                    self.close()
                
                elif msgcls in (messages.Keepalive, messages.RejectMsg):
                    # No need to respond at this level
                    pass
                
                # Delegated handlers
                elif msgcls == messages.TransferSegment:
                    self.recv_xfer_data(transfer_id=pkt.payload.transfer_id,
                                      data=pkt.payload.getfieldval('data'),
                                      flags=pkt.getfieldval('flags'))
                elif msgcls == messages.TransferAck:
                    self.recv_xfer_ack(pkt.payload.transfer_id, pkt.payload.length)
                elif msgcls == messages.TransferRefuse:
                    self.recv_xfer_refuse(pkt.payload.transfer_id, pkt.flags)
                
                else:
                    # Bad RX message
                    raise RejectError(messages.RejectMsg.REASON_UNKNOWN)
                
            except RejectError as err:
                self.send_reject(err.reason, pkt)
    
    def send_contact_header(self):
        flag_names = []
        if self._config.ssl_ctx:
            flag_names.append('CAN_TLS')
        
        options = dict(
            flags=combine_flags(flag_names),
        )
        
        pkt = contact.Head()/contact.ContactV4(**options)
        self.send_message(pkt)
        return pkt
    
    def merge_contact_params(self):
        ''' Combine local and peer contact headers to contact configuration.
        '''
        self.__logger.debug('Contact negotiation')
        
        this_can_tls = (self._conhead_this.flags & contact.ContactV4.FLAG_CAN_TLS)
        peer_can_tls = (self._conhead_peer.flags & contact.ContactV4.FLAG_CAN_TLS)
        self._tls_attempt = (this_can_tls and peer_can_tls)
    
    def send_sess_init(self):
        options = dict(
            keepalive=self._config.keepalive_time,
            segment_mru=self._config.segment_size,
            eid_data=self._config.eid.encode('utf8'),
        )
        
        pkt = messages.MessageHead()/messages.SessionInit(**options)
        self.send_message(pkt)
        return pkt
    
    def merge_session_params(self):
        ''' Combine local and peer SESS_INIT parameters.
        '''
        self.__logger.debug('Session negotiation')
        
        self._keepalive_time = min(self._sessinit_this.keepalive,
                                   self._sessinit_peer.keepalive)
        self.__logger.debug('KEEPALIVE time %d', self._keepalive_time)
        self._idle_time = self._config.idle_time
        self._keepalive_reset()
        self._idle_reset()
        
        self._send_segment_size = min(self._config.segment_size,
                                      self._sessinit_peer.segment_mru)
        self.__logger.debug('TX seg size %d', self._send_segment_size)
        
        self._do_send_ack_inter = True
        self._do_send_ack_final = True
    
    def send_raw(self, size):
        ''' Pop some data from the TX queue.
        '''
        data = self.__tx_buf[:size]
        if data:
            self.__logger.debug('TX popping %d of %d', len(data), len(self.__tx_buf))
        self.__tx_buf = self.__tx_buf[len(data):]
        
        self.send_buffer_decreased(len(self.__tx_buf))
        return data
    
    def send_message(self, pkt):
        ''' Send a full message (or contact header).
        
        :param pkt: The message packet to send.
        '''
        self.__logger.info('TX: %s', repr(pkt))
        pkt_data = str(pkt)
        if self.DO_DEBUG_DATA:
            self.__logger.debug('TX packet data: %s', pkt_data.encode('hex'))
        
        self.__tx_buf += pkt_data
        self.send_ready()
        
        self._keepalive_reset()
        self._idle_reset()
    
    def send_reject(self, reason, pkt=None):
        ''' Send a message rejection response.
        
        :param reason: The reject reason code.
        :type reason: int
        :param pkt: The message being rejected (optional).
        :type pkt: The orignal :py:class:`MessageHead` packet.
        '''
        rej_load = messages.RejectMsg(reason=reason)
        if pkt is not None:
            rej_load.rej_msg_id = pkt.msg_id
        self.send_message(messages.MessageHead()/rej_load)
    
    def do_sess_term(self, reason=None):
        self._wait_sess_term = True
        flg_names = []
        if reason is not None:
            flg_names.append('R')
        
        self.send_message(messages.MessageHead()
                          / messages.SessionTerm(flags=combine_flags(flg_names), reason=reason))
    
    def start(self):
        ''' Main state machine of the agent contact. '''
        self._conhead_peer = None
        self._conhead_this = None
        self._in_conn = False
        self._sessinit_peer = None
        self._sessinit_this = None
        self._in_sess = False
        
        if not self._as_passive:
            # Passive side listens first
            self._conhead_this = self.send_contact_header().payload

    def recv_xfer_data(self, transfer_id, data, flags):
        ''' Handle reception of XFER_DATA message.
        
        :param transfer_id: The bundle ID number.
        :type transfer_id: int
        :param data: The segment data.
        :type data: str
        '''
        self.__logger.debug('XFER_DATA %d %s', transfer_id, flags)
        if not self._in_sess:
            raise RejectError(messages.RejectMsg.REASON_UNEXPECTED)
        
    def recv_xfer_ack(self, transfer_id, length):
        ''' Handle reception of XFER_ACK message.
        
        :param transfer_id: The bundle ID number.
        :type transfer_id: int
        :param length: The acknowledged length.
        :type length: int
        '''
        self.__logger.debug('XFER_ACK %d %s', transfer_id, length)
        if not self._in_sess:
            raise RejectError(messages.RejectMsg.REASON_UNEXPECTED)
        
    def recv_xfer_refuse(self, transfer_id, reason):
        ''' Handle reception of XFER_REFUSE message.
        
        :param transfer_id: The bundle ID number.
        :type transfer_id: int
        :param reason: The refusal reason code.
        :type reason: int
        '''
        self.__logger.debug('XFER_REFUSE %d %s', transfer_id, reason)
        if not self._in_sess:
            raise RejectError(messages.RejectMsg.REASON_UNEXPECTED)

    def send_xfer_data(self, transfer_id, data, flg, ext=[]):
        ''' Send a XFER_DATA message.
        
        :param transfer_id: The bundle ID number.
        :type transfer_id: int
        :param data: The segment data.
        :type data: str
        :param flg: Data flags for :py:class:`TransferSegment`
        :type flg: int
        :param ext: Extension items for the starting segment only.
        :type ext: list
        '''
        if not self._in_sess:
            raise RuntimeError('Attempt to transfer before session established')
        if ext and not flg & messages.TransferSegment.FLAG_START:
            raise RuntimeError('Cannot send extension items outside of START message')
        
        self.send_message(messages.MessageHead()/
                          messages.TransferSegment(transfer_id=transfer_id,
                                                   flags=flg,
                                                   data=data,
                                                   ext_items=ext))
        
    def send_xfer_ack(self, transfer_id, length, flg):
        ''' Send a XFER_ACK message.
        
        :param transfer_id: The bundle ID number.
        :type transfer_id: int
        :param length: The acknowledged length.
        :type length: int
        :param flg: Data flags for :py:class:`TransferAck`
        :type flg: int
        '''
        if not self._in_sess:
            raise RuntimeError('Attempt to transfer before session established')
        
        self.send_message(messages.MessageHead()/
                          messages.TransferAck(transfer_id=transfer_id,
                                               flags=flg,
                                               length=length))
    
    def send_xfer_refuse(self, transfer_id, reason):
        ''' Send a XFER_REFUSE message.
        
        :param transfer_id: The bundle ID number.
        :type transfer_id: int
        :param reason: The refusal reason code.
        :type reason: int
        '''
        if not self._in_sess:
            raise RuntimeError('Attempt to transfer before session established')
        
        self.send_message(messages.MessageHead()/
                          messages.TransferRefuse(transfer_id=transfer_id,
                                                  flags=reason))
    

class BundleItem(object):
    ''' State for RX and TX full bundles.
    '''
    def __init__(self):
        self.transfer_id = None
        self.file = None

class ContactHandler(Messenger, dbus.service.Object):
    ''' A bus interface to the contact message handler.
    
    :param hdl_kwargs: Arguments to :py:cls:`Messenger` constructor.
    :type hdl_kwargs: dict
    :param bus_kwargs: Arguments to :py:cls:`dbus.service.Object` constructor.
    :type bus_kwargs: dict
    '''
    def __init__(self, hdl_kwargs, bus_kwargs):
        self.__logger = logging.getLogger(self.__class__.__name__)
        Messenger.__init__(self, **hdl_kwargs)
        dbus.service.Object.__init__(self, **bus_kwargs)
        # Transmit state
        #: Next sequential bundle ID
        self._tx_next_id = 1
        #: Pending TX bundles (as BundleItem)
        self._tx_bundles = []
        #: Names of pending TX bundles
        self._tx_map = {}
        #: Active TX bundle
        self._tx_tmp = None
        #: Total segment count
        self._tx_seg_num = None
        #: Current segment index
        self._tx_seg_ix = None
        self._process_queue_pend = None
        
        # Receive state
        #: Active RX bundle
        self._rx_tmp = None
        #: Full RX bundles pending delivery (as BundleItem)
        self._rx_bundles = []
        #: Names of pending RX bundles
        self._rx_map = {}
    
    def next_id(self):
        ''' Get the next available bundle ID number.
        
        :return: A valid bundle ID.
        :rtype: int
        '''
        bid = self._tx_next_id
        self._tx_next_id += 1
        return bid
    
    def _rx_setup(self, transfer_id):
        ''' Begin reception of a transfer. '''
        self._rx_tmp = BundleItem()
        self._rx_tmp.transfer_id = transfer_id
        self._rx_tmp.file = StringIO.StringIO()
        
        self.recv_bundle_started(str(transfer_id))
    
    def _rx_teardown(self):
        self._rx_tmp = None
    
    def recv_xfer_data(self, transfer_id, data, flags):
        Messenger.recv_xfer_data(self, transfer_id, data, flags)
        
        if flags & messages.TransferSegment.FLAG_START:
            self._rx_setup(transfer_id)
            self._ack_inter_time_last = None
        
        elif self._rx_tmp is None or self._rx_tmp.transfer_id != transfer_id:
            # Each ID in sequence after start must be identical
            raise RejectError(messages.RejectMsg.REASON_UNEXPECTED)
        
        self._rx_tmp.file.write(data)
        
        if flags & messages.TransferSegment.FLAG_END:
            if self._do_send_ack_final:
                self.send_xfer_ack(transfer_id, self._rx_tmp.file.tell(), flags)
            
            item = self._rx_tmp
            self._rx_bundles.append(item)
            self._rx_map[item.transfer_id] = item
            
            self.__logger.info('Finished RX size %d', item.file.tell())
            self.recv_bundle_finished(str(item.transfer_id))
            self._rx_teardown()
        else:
            if self._do_send_ack_inter:
                nowtime = datetime.datetime.utcnow()
                if self._ack_inter_time_last is None or nowtime - self._ack_inter_time_last > self._ack_inter_time_min:
                    self.send_xfer_ack(transfer_id, self._rx_tmp.file.tell(), flags)
                    self._ack_inter_time_last = nowtime
    
    def recv_xfer_ack(self, transfer_id, length):
        Messenger.recv_xfer_ack(self, transfer_id, length)
        
        item = self._tx_map[transfer_id]
        if length == item.file.tell():
            if not self._do_send_ack_final:
                raise RejectError(messages.RejectMsg.REASON_UNEXPECTED)
            
            self.send_bundle_finished(str(item.transfer_id), 'success')
            self._tx_map.pop(transfer_id)
        else:
            if not self._do_send_ack_inter:
                raise RejectError(messages.RejectMsg.REASON_UNEXPECTED)
    
    def recv_xfer_refuse(self, transfer_id, reason):
        Messenger.recv_xfer_refuse(self, transfer_id, reason)
        
        self.send_bundle_finished(transfer_id, 'refused with code %s', reason)
        self._tx_map.pop(transfer_id)
        
        # interrupt in-progress
        if self._tx_tmp is not None and self._tx_tmp.transfer_id == transfer_id:
            self._tx_teardown()
    
    IFACE = 'org.ietf.dtn.tcpcl.Contact'
    
    @dbus.service.method(IFACE, in_signature='', out_signature='b')
    def is_secure(self):
        return Connection.is_secure(self)
    
    @dbus.service.method(IFACE, in_signature='', out_signature='')
    def close(self):
        if tuple(self.locations):
            self.remove_from_connection()
            
        Messenger.close(self)
    
    @dbus.service.method(IFACE, in_signature='ay', out_signature='s')
    def send_bundle_data(self, data):
        ''' Send bundle data directly.
        '''
        
        # byte array to str
        data = ''.join([chr(val) for val in data])
        
        item = BundleItem()
        item.file = StringIO.StringIO(data)
        return str(self._add_queue_item(item))
    
    @dbus.service.method(IFACE, in_signature='s', out_signature='s')
    def send_bundle_file(self, filepath):
        ''' Send a bundle from the filesystem.
        '''
        item = BundleItem()
        item.file = open(filepath, 'rb')
        return str(self._add_queue_item(item))
    
    def _add_queue_item(self, item):
        if item.transfer_id is None:
            item.transfer_id = self.next_id()
        
        self._tx_bundles.append(item)
        self._tx_map[item.transfer_id] = item
        
        self._process_queue_trigger()
        return item.transfer_id
    
    @dbus.service.method(IFACE, in_signature='', out_signature='as')
    def send_bundle_get_queue(self):
        return dbus.Array([str(bid) for bid in self._tx_map.keys()])
    
    @dbus.service.signal(IFACE, signature='s')
    def send_bundle_started(self, bid):
        pass
    
    @dbus.service.signal(IFACE, signature='ss')
    def send_bundle_finished(self, bid, result):
        pass
    
    @dbus.service.signal(IFACE, signature='s')
    def recv_bundle_started(self, bid):
        pass
    
    @dbus.service.signal(IFACE, signature='s')
    def recv_bundle_finished(self, bid):
        pass
    
    @dbus.service.method(IFACE, in_signature='', out_signature='as')
    def recv_bundle_get_queue(self):
        return dbus.Array([str(bid) for bid in self._rx_map.keys()])
    
    @dbus.service.method(IFACE, in_signature='s', out_signature='ay')
    def recv_bundle_pop_data(self, bid):
        bid = int(bid)
        item = self._rx_map.pop(bid)
        self._rx_bundles.remove(item)
        item.file.seek(0)
        return item.file.read()
    
    @dbus.service.method(IFACE, in_signature='ss', out_signature='')
    def recv_bundle_pop_file(self, bid, filepath):
        bid = int(bid)
        item = self._rx_map.pop(bid)
        self._rx_bundles.remove(item)
        item.file.seek(0)
        
        import shutil
        out_file = open(filepath, 'wb')
        shutil.copyfileobj(item.file, out_file)
    
    def send_buffer_decreased(self, buf_use):
        if self._send_segment_size is None:
            return
        
        if buf_use < 2 * self._send_segment_size:
            self._process_queue_trigger()
    
    def _tx_teardown(self):
        ''' Clear the TX bundle state. '''
        self._tx_tmp = None
        self._tx_seg_ix = None
        self._tx_seg_num = None
    
    def _process_queue_trigger(self):
        if self._process_queue_pend is None:
            self._process_queue_pend = glib.idle_add(self._process_queue)
    
    def _process_queue(self):
        ''' Perform the next TX segment if possible.
        '''
        self._process_queue_pend = None
        self.__logger.debug('Processing queue of %d items', len(self._tx_bundles))
        
        # work from the head of the list
        if self._tx_tmp is None:
            if not self._tx_bundles:
                # nothing to do
                return
            self._tx_tmp = self._tx_bundles.pop(0)
            
            self._tx_tmp.file.seek(0, os.SEEK_END)
            octet_count = self._tx_tmp.file.tell()
            self._tx_tmp.file.seek(0)
            self._tx_seg_num = math.ceil(octet_count / float(self._send_segment_size))
            self._tx_seg_ix = 0
            
            self.send_bundle_started(str(self._tx_tmp.transfer_id))
        
        # send next segment
        data = self._tx_tmp.file.read(self._send_segment_size)
        flg = 0
        xfer_ext = []
        if self._tx_seg_ix == 0:
            flg |= messages.TransferSegment.FLAG_START
            xfer_ext.append(
                messages.TransferExtendHeader()/xferextend.Length(total_length=octet_count)
            )
        if self._tx_seg_ix == self._tx_seg_num - 1:
            flg |= messages.TransferSegment.FLAG_END
        
        # Next segment of data
        self.send_xfer_data(self._tx_tmp.transfer_id, data, flg, xfer_ext)
        self._tx_seg_ix += 1
        
        if flg & messages.TransferSegment.FLAG_END:
            if not self._do_send_ack_final:
                self.send_bundle_finished(str(self._tx_tmp.transfer_id), 'unacknowledged')
                self._tx_map.pop(self._tx_tmp.transfer_id)
            
            # done sending segments regardless
            self._tx_teardown()

class Agent(dbus.service.Object):
    ''' Overall agent behavior. '''
    
    def __init__(self, config, bus_kwargs):
        self.__logger = logging.getLogger(self.__class__.__name__)
        dbus.service.Object.__init__(self, **bus_kwargs)
        self._config = config
        self._on_stop = None
        
        self._bindsock = None
        self._obj_id = 0
        self._handlers = []
    
    def __del__(self):
        self.stop()
    
    def _get_obj_path(self):
        hdl_id = self._obj_id
        self._obj_id += 1
        return '/org/ietf/dtn/tcpcl/Contact{0}'.format(hdl_id)
    
    def _bind_handler(self, **kwargs):
        if not self._config.bus_conn:
            return
        
        path = self._get_obj_path()
        hdl = ContactHandler(hdl_kwargs=kwargs,
                           bus_kwargs=dict(conn=self._config.bus_conn, object_path=path))
        self.__logger.info('New handler at "%s"', path)
        
        self._handlers.append(hdl)
        if not self._bindsock:
            hdl.set_on_close(lambda: self.stop())
        
        return hdl
    
    IFACE = 'org.ietf.dtn.tcpcl.Agent'
    
    def set_on_close(self, func):
        ''' Set a callback to be run when this agent is stopped.
        
        :param func: The callback, which takes no arguments.
        '''
        self._on_stop = func
    
    @dbus.service.method(IFACE, in_signature='')
    def stop(self):
        if self._bindsock:
            self.__logger.info('Un-listening')
            try:
                self._bindsock.shutdown(socket.SHUT_RDWR)
            except socket.error as err:
                self.__logger.error('Bind socket shutdown error: %s', err)
            self._bindsock.close()
            self._bindsock = None
        
        for hdl in self._handlers:
            hdl.close()
        
        if tuple(self.locations):
            self.remove_from_connection()
            
        if self._on_stop:
            self._on_stop()
    
    def listen(self, address, port):
        ''' Begin listening for incoming connections and defer handling
        connections to `glib` event loop.
        '''
        sock = socket.socket(socket.AF_INET)
        sock.bind((address, port))
        
        self.__logger.info('Listening')
        self._bindsock = sock
        self._bindsock.listen(1)
        glib.io_add_watch(self._bindsock, glib.IO_IN, self._accept)
    
    def _accept(self, bindsock, *args, **kwargs):
        ''' Callback to handle incoming connections.
        
        :return: True to continue listening.
        '''
        newsock, fromaddr = bindsock.accept()
        self.__logger.info('Connecting')
        hdl = self._bind_handler(config=self._config, sock=newsock, fromaddr=fromaddr)
        
        try:
            hdl.start()
        except Exception as err:
            self.__logger.warning('Failed: %s', err)
        
        return True
    
    def connect(self, address, port):
        ''' Initiate an outgoing connection and defer handling state to
        `glib` event loop.
        '''
        self.__logger.info('Connecting')
        sock = socket.socket(socket.AF_INET)
        sock.connect((address, port))
        
        hdl = self._bind_handler(config=self._config, sock=sock, toaddr=(address,port))
        hdl.start()

def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def main():
    parser = argparse.ArgumentParser()
    subp = parser.add_subparsers(dest='action', help='action')
    parser.add_argument('--eid', type=unicode, 
                        help='This node EID')
    parser.add_argument('--keepalive', type=int, 
                        help='Keepalive time in seconds')
    parser.add_argument('--idle', type=int, 
                        help='Idle time in seconds')
    parser.add_argument('--bus-service', type=str, 
                        help='D-Bus service name')
    parser.add_argument('--tls-disable', dest='tls_enable', default=True, action='store_false', 
                        help='Disallow use of TLS on this endpoint')
    parser.add_argument('--tls-require', default=None, type=str2bool,
                        help='Require the use of TLS for all sessions')
    parser.add_argument('--tls-ca', type=str, 
                        help='Filename for CA chain')
    parser.add_argument('--tls-cert', type=str, 
                        help='Filename for X.509 certificate')
    parser.add_argument('--tls-key', type=str, 
                        help='Filename for X.509 private key')
    parser.add_argument('--tls-dhparam', type=str, 
                        help='Filename for DH parameters')
    
    parser_listen = subp.add_parser('listen', 
                                    help='Listen for TCP connections')
    parser_listen.add_argument('--address', type=str, default='',
                               help='Listen name or address')
    parser_listen.add_argument('--port', type=int, default=4556,
                               help='Listen TCP port')
    
    parser_conn = subp.add_parser('connect', 
                                  help='Make a TCP connection')
    parser_conn.add_argument('address', type=str, 
                             help='Host name or address')
    parser_conn.add_argument('--port', type=int, default=4556,
                             help='Host TCP port')
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.DEBUG)
    logging.debug('command args: %s', args)
    
    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)
    
    config = Config()
    
    config.bus_conn = dbus.bus.BusConnection(dbus.bus.BUS_SESSION)
    if args.bus_service:
        bus_serv = dbus.service.BusName(bus=config.bus_conn, name=args.bus_service, do_not_queue=True)
        logging.info('Registered as "%s"', bus_serv.get_name())
    
    if args.tls_enable:
        config.ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        config.ssl_ctx.set_ciphers(ssl._DEFAULT_CIPHERS)
        if args.tls_ca:
            config.ssl_ctx.load_verify_locations(args.tls_ca)
        if args.tls_cert:
            config.ssl_ctx.load_cert_chain(args.tls_cert, args.tls_key)
        if args.tls_dhparam:
            config.ssl_ctx.load_dh_params(args.tls_dhparam)
    
    config.eid = args.eid
    config.tls_require = args.tls_require
    
    if args.keepalive:
        config.keepalive_time = args.keepalive
    
    if args.idle:
        config.idle_time = args.idle
    else:
        config.idle_time = 2 * config.keepalive_time
    
    agent = Agent(config, bus_kwargs=dict(conn=config.bus_conn, object_path='/org/ietf/dtn/tcpcl/Agent'))
    if args.action == 'listen':
        #config.ssl_ctx.verify_mode = ssl.CERT_OPTIONAL
        #onfig.ssl_ctx.check_hostname = False
        agent.listen(args.address, args.port)
    elif args.action == 'connect':
        if args.tls_enable:
            if False:
                config.ssl_ctx.verify_mode = ssl.CERT_REQUIRED
                config.ssl_ctx.check_hostname = True
            else:
                config.ssl_ctx.verify_mode = ssl.CERT_NONE
                config.ssl_ctx.check_hostname = False
        agent.connect(args.address, args.port)
    
    eloop = glib.MainLoop()
    agent.set_on_close(lambda: eloop.quit())
    try:
        eloop.run()
    except KeyboardInterrupt:
        pass
    agent.stop()

if __name__ == '__main__':
    sys.exit(main())
