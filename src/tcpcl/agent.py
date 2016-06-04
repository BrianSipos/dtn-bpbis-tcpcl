'''
Implementation of a symmetric TCPCL agent.
'''

import sys
import logging
import argparse
import socket
import ssl
import glib
import dbus.bus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from scapy import packet
from tcpcl import contact, messages

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
        #self.tls_attempt = True
        self.tls_require = True
        self.eid = ''
        self.keepalive_time = 0
        self.idle_time = 0
        #: Maximum size of transmit segments in octets
        self.segment_size = 100#10240

class Connection(object):
    ''' Optionally secured socket connection.
    
    :param sock: The unsecured socket to wrap.
    :param as_server: True if this is the server-side of the connection.
    '''
    def __init__(self, sock, as_server, peer_name):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self._on_close = None
        self._as_server = as_server
        self._peer_name = peer_name
        #: The raw socket
        self._s_notls = None
        #: Optionally secured socket
        self._s_tls = None
        
        #: listener for _s_notls socket
        self._avail_rx_notls_id = None
        #: optional listener for _s_tls socket
        self._avail_rx_tls_id = None
        
        self._replace_socket(sock)
    
    def is_secure(self):
        ''' Determine if TLS is established.
        
        :return: True if operating with TLS.
        '''
        return (self._s_tls is not None)
    
    def __unlisten_notls(self):
        if self._avail_rx_notls_id is not None:
            glib.source_remove(self._avail_rx_notls_id)
            self._avail_rx_notls_id = None
    
    def __unlisten_tls(self):
        if self._avail_rx_tls_id is not None:
            glib.source_remove(self._avail_rx_tls_id)
            self._avail_rx_tls_id = None
    
    def _replace_socket(self, sock):
        ''' Replace the socket used by this object.
        Any current socket is left open.
        
        :param sock: The new socket.
        :type sock: :py:class:`socket.socket`
        :return: The old socket.
        '''
        old = self._s_notls
        self.__unlisten_notls()
        
        self._s_notls = sock
        if self._s_notls is not None:
            self._avail_rx_notls_id = glib.io_add_watch(self._s_notls, glib.IO_IN, self._avail_rx_notls)
            #self._avail_tx_notls_id = glib.io_add_watch(self._s_notls, glib.IO_OUT, self._avail_tx_notls)
        
        return old
    
    def set_on_stop(self, func):
        ''' Set a callback to be run when this connection is closed.
        
        :param func: The callback, which takes no arguments.
        '''
        self._on_close = func
    
    def close(self):
        ''' Close the entire connection cleanly.
        '''
        if not self._s_notls:
            return
        self.__logger.info('Closing connection')
        
        self.__unlisten_tls()
        self.__unlisten_notls()
        
        # Best effort to close active socket
        for sock in (self._s_tls, self._s_notls):
            if sock is None:
                continue
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
            sock.close()
        
        self._s_notls = None
        self._s_tls = None
        
        if self._on_close:
            self._on_close()
    
    def secure(self, ssl_ctx):
        ''' Add a TLS connection layer (if not present).
        
        :param ssl_ctx: The context to use for security.
        :type ssl_ctx: :py:class:`ssl.SSLContext`
        :raise ssl.SSLError: If the negotiation fails.
        '''
        if self._s_tls:
            return
        
        if self._as_server:
            self._s_tls = ssl_ctx.wrap_socket(self._s_notls,
                                              server_side=True,
                                              do_handshake_on_connect=False)
        else:
            self._s_tls = ssl_ctx.wrap_socket(self._s_notls,
                                              server_hostname=self._peer_name,
                                              do_handshake_on_connect=False)
        
        self.__logger.debug('Negotiating TLS...')
        try:
            self._s_tls.do_handshake()
        except ssl.SSLError as err:
            self.__logger.debug('TLS failed: {0}'.format(err))
            # leave non-TLS socket in place
            #self._s_tls = None
            self.unsecure()
            raise
            
        self.__logger.info('TLS secured with {0}'.format(self._s_tls.cipher()))
        
        self._avail_rx_tls_id = glib.io_add_watch(self._s_tls, glib.IO_IN, self._avail_rx_tls)
    
    def unsecure(self):
        ''' Remove any TLS connection layer (if present).
        '''
        if not self._s_tls:
            return
        
        self.__logger.debug('Unsecuring TLS...')
        self.__unlisten_tls()
        
        # Keep the unsecured socket
        new_sock = self._s_tls.unwrap()
        self._s_tls = None
        self._replace_socket(new_sock)
    
    def _conn_name(self):
        ''' A name for the connection type. '''
        if self.is_secure():
            return 'secure'
        else:
            return 'plain'
    
    def _avail_rx_notls(self, *args, **kwargs):
        ''' Callback for new :py:obj:`_s_notls` data. '''
        if self._s_tls is not None:
            return True
        
        rx_data = self._s_notls.recv(1024)
        if len(rx_data) == 0:
            self.close()
            return False
        
        self._rx_proxy(rx_data)
        return True
    
    def _avail_rx_tls(self, *args, **kwargs):
        ''' Callback for new :py:obj:`_s_tls` data. '''
        if self._s_tls is None:
            return True
        
        rx_data = self._s_tls.recv(1024)
        if len(rx_data) == 0:
            # Connection closed
            self.close()
            return False
        
        self._rx_proxy(rx_data)
        return True
    
    def _rx_proxy(self, data):
        self.__logger.debug('Received {0} octets ({1})'.format(len(data), self._conn_name()))
        self.recv_raw(data)
    
    def recv_raw(self, data):
        ''' Handler for received blocks of data.
        
        :param data: The received data.
        :type data: str
        '''
        pass
    
    def send_raw(self, data):
        ''' Send a block of data.
        
        :param data: The data to send.
        :type data: str
        :return: True if the data was sent.
        :rtype: bool
        '''
        sock = self._s_tls or self._s_notls
        if sock is None:
            self.__logger.warning('Message on closed socket')
            return False
        
        self.__logger.debug('Sending message {0} octets ({1})'.format(len(data), self._conn_name()))
        
        sock.send(data)
        return True

class RejectError(Exception):
    ''' Allow recv_ handlers to reject the message.
    
    :param reason: The rejection reason.
    :type reason: int
    '''
    def __init__(self, reason=None):
        Exception.__init__('rejected')
        self.reason = reason

class HandlerBase(Connection):
    ''' Individual contact handler. '''
    
    def __init__(self, config, sock, fromaddr=None, toaddr=None):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self._config = config
        
        # negotiated parameters
        self._keepalive_time = 0
        self._idle_time = 0
        self._send_segment_size = None
        self._do_send_ack = None
        self._do_send_frag = None
        self._do_send_refuse = None
        self._do_send_length = None
        
        self._keepalive_timer_id = None
        self._idle_timer_id = None
        
        self._head_this = None
        self._head_peer = None
        # Assume socket is ready
        self._is_open = True
        # If false, still waiting on contact header negotiation
        self._in_conn = False
        self._wait_shutdown = False
        
        self._from = fromaddr
        self._to = toaddr
        self._rbuf = ''
        
        # now set up connection
        if fromaddr:
            as_server = True
            peer_name = fromaddr[0]
        else:
            as_server = False
            peer_name = toaddr[0]
        Connection.__init__(self, sock, as_server, peer_name)
    
    def is_server(self):
        return (self._from is not None)
    
    def close(self):
        self._idle_stop()
        self._keepalive_stop()
        super(HandlerBase, self).close()
    
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
        self.do_shutdown(messages.Shutdown.REASON_IDLE)
        return False
    
    def recv_raw(self, data):
        ''' Attempt to extract a message from the current read buffer.
        '''
        self._idle_reset()
        if self._in_conn:
            msgcls = messages.MessageHead
        else:
            msgcls = contact.Head
        # always append
        self._rbuf += data
        
        # Probe for full message (by reading back encoded data)
        pkt = msgcls(self._rbuf)
        pkt_data = str(pkt)
        if not self._rbuf.startswith(pkt_data):
            return
        self.__logger.debug('Matched message {0} octets'.format(len(pkt_data)))
        self.__logger.debug('RX data: {0}'.format(pkt_data.encode('hex')))
        
        # Keep final padding as future data
        testload = pkt
        while True:
            if testload is None or isinstance(testload, packet.NoPayload):
                self._rbuf = ''
                break
            if isinstance(testload, packet.Padding):
                self._rbuf = testload.load
                break
            
            testload = testload.payload
        self.__logger.debug('Remain {0} octets'.format(len(self._rbuf)))
        
        self.handle_message(pkt)
    
    def handle_message(self, pkt):
        ''' Handle a received full message (or contact header).
        
        :param pkt: The message packet received.
        '''
        self.__logger.info('RX: {0}'.format(repr(pkt)))
        
        if isinstance(pkt, contact.Head):
            if pkt.magic != contact.MAGIC_HEAD:
                raise ValueError('Contact header with bad magic: {0}'.format(pkt.magic.encode('hex')))
            if pkt.version != 4:
                raise ValueError('Contact header with bad version: {0}'.format(pkt.version))
            self._head_peer = pkt.payload
            self._in_conn = True
            self.merge_options()
            
            # Client initiates STARTTLS
            if not self.is_server() and not self.is_secure() and self._tls_attempt:
                self.send_message(messages.MessageHead()/messages.StartTls())
        else:
            # Some payloads are empty and scapy will not construct them
            msgcls = pkt.guess_payload_class('')
            
            try: # Allow rejection from any of these via RejectError
                if msgcls == messages.Shutdown:
                    # Send a reply (if not the initiator)
                    if not self._wait_shutdown:
                        self.do_shutdown()
                    
                    self.close()
                
                elif msgcls in (messages.Keepalive, messages.RejectMsg):
                    # No need to respond at this level
                    pass
                
                elif msgcls == messages.StartTls:
                    # Server response to STARTTLS
                    if self.is_server():
                        self.send_message(messages.MessageHead()/messages.StartTls())
                    
                    # Either case, STARTTLS has been exchanged
                    try:
                        self.secure(self._config.ssl_ctx)
                    except ssl.SSLError as err:
                        pass
                    
                    if self.is_secure():
                        # Re-negotiate contact
                        self._in_conn = False
                        self.send_contact_header()
                    else:
                        # TLS negotiation failure
                        if self._config.tls_require:
                            self.do_shutdown(messages.Shutdown.REASON_TLS_FAIL)
                        else:
                            raise RejectError(messages.RejectMsg.REASON_UNSUPPORTED)
                
                # Delegated handlers
                elif msgcls == messages.BundleLength:
                    self.recv_length(pkt.payload.bundle_id, pkt.payload.length)
                elif msgcls == messages.DataSegment:
                    self.recv_segment(pkt.payload.bundle_id, pkt.payload.data, pkt.flags)
                elif msgcls == messages.AckSegment:
                    self.recv_ack(pkt.payload.bundle_id, pkt.payload.length)
                elif msgcls == messages.RefuseBundle:
                    self.recv_refuse(pkt.payload.bundle_id, pkt.flags)
                
                else:
                    # Bad RX message
                    raise RejectError(messages.RejectMsg.REASON_UNKNOWN)
                
            except RejectError as err:
                self.send_reject(err.reason, pkt)
    
    def send_contact_header(self):
        optlist = [
            contact.OptionHead()/contact.OptionEid(eid_data=self._config.eid.encode('utf8')),
            contact.OptionHead()/contact.OptionTls(accept=contact.MessageRxField.FLAG_REQUIRE),
            contact.OptionHead()/contact.OptionKeepalive(keepalive=self._config.keepalive_time),
            contact.OptionHead()/contact.OptionMru(segment_size=self._config.segment_size),
            #contact.OptionHead()/contact.OptionLength(flags=contact.MessageRxField.FLAG_ALLOW),
            #contact.OptionHead()/contact.OptionAck(flags=contact.MessageRxField.FLAG_ALLOW),
            #contact.OptionHead()/contact.OptionRefuse(flags=contact.MessageRxField.FLAG_ALLOW),
            #flags='ENA_ACK+ENA_LENGTH+ENA_REFUSE',
        ]
        pkt = contact.Head()/contact.ContactV4(options=optlist)
        self.send_message(pkt)
        return pkt
    
    def merge_options(self):
        ''' Combine local and peer contact headers to contact configuration.
        '''
        self.__logger.debug('Contact negotiation')
        
        def send_policy(flag):
            self.__logger.debug('flag %d', flag)
            return (flag in (contact.MessageRxField.FLAG_ALLOW,
                             contact.MessageRxField.FLAG_REQUIRE))
        
        self._tls_attempt = (send_policy(self._head_this.find_option(contact.OptionTls).accept)
                             & send_policy(self._head_this.find_option(contact.OptionTls).accept))
        
        self._keepalive_time = min(self._head_this.find_option(contact.OptionKeepalive).keepalive,
                                   self._head_peer.find_option(contact.OptionKeepalive).keepalive)
        self._idle_time = self._config.idle_time
        self._keepalive_reset()
        self._idle_reset()
        
        self._send_segment_size = min(self._config.segment_size,
                                      self._head_peer.find_option(contact.OptionMru).segment_size)
        self.__logger.debug('TX seg size {0}'.format(self._send_segment_size))
        
        self._do_send_length = send_policy(self._head_this.find_option(contact.OptionLength).accept)
        self._do_send_ack = send_policy(self._head_this.find_option(contact.OptionAck).accept)
        self._do_send_refuse = send_policy(self._head_this.find_option(contact.OptionRefuse).accept)
        self._do_send_frag = False
    
    def send_message(self, pkt):
        ''' Send a full message (or contact header).
        
        :param pkt: The message packet to send.
        '''
        self.__logger.info('TX: {0}'.format(repr(pkt)))
        pkt_data = str(pkt)
        self.__logger.debug('TX data: {0}'.format(pkt_data.encode('hex')))
        self.send_raw(pkt_data)
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
            rej_load.rej_id = pkt.msg_id
            rej_load.rej_flags = pkt.flags
        self.send_message(messages.MessageHead()/rej_load)
    
    def do_shutdown(self, reason=None):
        self._wait_shutdown = True
        flags = 0
        if reason is not None:
            flags |= messages.Shutdown.FLAG_REASON
        self.send_message(messages.MessageHead(flags=flags)
                          / messages.Shutdown(reason=reason))
    
    def start(self):
        ''' Main state machine of the agent contact. '''
        self._in_conn = False
        self._head_peer = None
        self._head_this = self.send_contact_header().payload
    
    
    def recv_length(self, bundle_id, length):
        ''' Handle reception of LENGTH message.
        
        :param bundle_id: The bundle ID number.
        :type bundle_id: int
        :param length: The bundle length.
        :type length: int
        '''
    def recv_segment(self, bundle_id, data, flags):
        ''' Handle reception of DATA_SEGMENT message.
        
        :param bundle_id: The bundle ID number.
        :type bundle_id: int
        :param data: The segment data.
        :type data: str
        '''
    def recv_ack(self, bundle_id, length):
        ''' Handle reception of DATA_ACKNOWLEDGE message.
        
        :param bundle_id: The bundle ID number.
        :type bundle_id: int
        :param length: The acknowledged length.
        :type length: int
        '''
    def recv_refuse(self, bundle_id, reason):
        ''' Handle reception of REFUSE message.
        
        :param bundle_id: The bundle ID number.
        :type bundle_id: int
        :param reason: The refusal reason code.
        :type reason: int
        '''
    
    def send_length(self, bundle_id, length):
        ''' Send a LENGTH message.
        
        :param bundle_id: The bundle ID number.
        :type bundle_id: int
        :param length: The bundle length.
        :type length: int
        '''
        self.send_message(messages.MessageHead()/
                          messages.BundleLength(bundle_id=bundle_id,
                                                length=length))
        
    def send_segment(self, bundle_id, data, flg):
        ''' Send a DATA_SEGMENT message.
        
        :param bundle_id: The bundle ID number.
        :type bundle_id: int
        :param data: The segment data.
        :type data: str
        :param flg: Data flags for :py:class:`DataSegment`
        :type flg: int
        '''
        self.send_message(messages.MessageHead(flags=flg)/
                          messages.DataSegment(bundle_id=bundle_id,
                                               data=data))
        
    def send_ack(self, bundle_id, length):
        ''' Send a DATA_ACKNOWLEDGE message.
        
        :param bundle_id: The bundle ID number.
        :type bundle_id: int
        :param length: The acknowledged length.
        :type length: int
        '''
        self.send_message(messages.MessageHead()/
                          messages.AckSegment(bundle_id=bundle_id,
                                              length=length))
    
    def send_refuse(self, bundle_id, reason):
        ''' Send a REFUSE message.
        
        :param bundle_id: The bundle ID number.
        :type bundle_id: int
        :param reason: The refusal reason code.
        :type reason: int
        '''
        self.send_message(messages.MessageHead(flags=reason)/
                          messages.RefuseBundle(bundle_id=bundle_id))
    

class BundleItem(object):
    ''' State for RX and TX full bundles.
    '''
    def __init__(self):
        self.bundle_id = None
        self.data = None

class ContactHandler(HandlerBase, dbus.service.Object):
    ''' A bus interface to the contact message handler.
    
    :param hdl_kwargs: Arguments to :py:cls:`HandlerBase` constructor.
    :type hdl_kwargs: dict
    :param bus_kwargs: Arguments to :py:cls:`dbus.service.Object` constructor.
    :type bus_kwargs: dict
    '''
    def __init__(self, hdl_kwargs, bus_kwargs):
        self.__logger = logging.getLogger(self.__class__.__name__)
        HandlerBase.__init__(self, **hdl_kwargs)
        dbus.service.Object.__init__(self, **bus_kwargs)
        # Transmit state
        #: Next sequential bundle ID
        self._tx_next_id = 1
        #: Pending TX bundles (as BundleItem)
        self._tx_bundles = []
        self._tx_map = {}
        
        # Receive state
        #: Active RX bundle ID
        self._rx_bid = None
        #: Partial reception buffer
        self._rx_buf = None
        #: Full RX bundles pending delivery (as BundleItem)
        self._rx_bundles = []
        self._rx_map = {}
    
    def next_id(self):
        ''' Get the next available bundle ID number.
        
        :return: A valid bundle ID.
        :rtype: int
        '''
        bid = self._tx_next_id
        self._tx_next_id += 1
        return bid
    
    def _rx_setup(self, bundle_id):
        self._rx_bid = bundle_id
        self._rx_buf = ''
        self.recv_bundle_started(str(bundle_id))
    
    def _rx_teardown(self):
        self._rx_bid = None
        self._rx_buf = None
    
    def recv_length(self, bundle_id, length):
        print 'length', bundle_id, length
        # reject if length is received mid-bundle
        if self._rx_buf or not self._do_send_length:
            raise RejectError(messages.RejectMsg.REASON_UNEXPECTED)
        self._rx_setup(bundle_id)
    
    def recv_segment(self, bundle_id, data, flags):
        print 'data', bundle_id, flags
        
        if flags & messages.DataSegment.FLAG_START:
            if self._do_send_length:
                # Start without a prior LENGTH
                if self._rx_bid is None:
                    raise RejectError(messages.RejectMsg.REASON_UNEXPECTED)
            else:
                # no LENGTH, this is start of RX
                self._rx_setup(bundle_id)
        
        elif self._rx_bid != bundle_id:
            # Each ID in sequence after start must be identical
            raise RejectError(messages.RejectMsg.REASON_UNEXPECTED)
        
        self._rx_buf += data
        if self._do_send_ack:
            self.send_ack(bundle_id, len(self._rx_buf))
        
        if flags & messages.DataSegment.FLAG_END:
            print 'Finished RX', self._rx_buf.encode('hex')
            item = BundleItem()
            item.bundle_id = self._rx_bid
            item.data = self._rx_buf
            self._rx_bundles.append(item)
            self._rx_map[item.bundle_id] = item
            
            self.recv_bundle_finished(str(bundle_id))
            self._rx_teardown()
    
    def recv_ack(self, bundle_id, length):
        print 'ack', bundle_id, length
        if not self._do_send_ack:
            raise RejectError(messages.RejectMsg.REASON_UNEXPECTED)
        
        item = self._tx_map[bundle_id]
        if length == len(item.data):
            self.send_bundle_finished(str(item.bundle_id), 'success')
            self._tx_map.pop(bundle_id)
    
    def recv_refuse(self, bundle_id, reason):
        print 'refuse', bundle_id, reason
        self.send_bundle_finished(bundle_id, 'refused with code {0}'.format(reason))
        self._tx_map.pop(bundle_id)
    
    IFACE = 'org.ietf.dtn.tcpcl.Contact'
    
    @dbus.service.method(IFACE, in_signature='', out_signature='b')
    def is_secure(self):
        return Connection.is_secure(self)
    
    @dbus.service.method(IFACE, in_signature='', out_signature='')
    def close(self):
        if tuple(self.locations):
            self.remove_from_connection()
            
        HandlerBase.close(self)
    
    @dbus.service.method(IFACE, in_signature='ay', out_signature='s')
    def send_bundle_data(self, data):
        
        # byte array to str
        data = ''.join([chr(val) for val in data])
        
        item = BundleItem()
        item.bundle_id = self.next_id()
        item.data = data
        self._tx_bundles.append(item)
        self._tx_map[item.bundle_id] = item
        
        glib.idle_add(self._process_queue)
        return str(item.bundle_id)
    
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
    
    @dbus.service.method(IFACE, in_signature='s', out_signature='ay')
    def recv_bundle_pop(self, bid):
        bid = int(bid)
        item = self._rx_map.pop(bid)
        self._rx_bundles.remove(item)
        return item.data
    
    def _process_queue(self):
        self.__logger.info('Processing queue of {0} items'.format(len(self._tx_bundles)))
        
        while self._tx_bundles:
            item = self._tx_bundles.pop(0)
            
            import math
            octet_count = len(item.data)
            seg_count = int(math.ceil(octet_count / float(self._send_segment_size)))
            
            self.send_bundle_started(str(item.bundle_id))
            
            if self._do_send_length:
                self.send_length(item.bundle_id, octet_count)
            
            for seg_ix in range(seg_count):
                # Range of bundle to send
                start_ix = self._send_segment_size * seg_ix
                end_ix = min(octet_count, start_ix + self._send_segment_size)
                
                flg = 0
                if seg_ix == 0:
                    flg |= messages.DataSegment.FLAG_START
                if seg_ix == seg_count - 1:
                    flg |= messages.DataSegment.FLAG_END
                
                self.send_segment(item.bundle_id, item.data[start_ix:end_ix], flg)
            
            if not self._do_send_ack:
                self.send_bundle_finished(str(item.bundle_id), 'unacknowledged')

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
        self.__logger.info('New handler at "{0}"'.format(path))
        
        self._handlers.append(hdl)
        if not self._bindsock:
            hdl.set_on_stop(lambda: self.stop())
        
        return hdl
    
    IFACE = 'org.ietf.dtn.tcpcl.Agent'
    
    def set_on_stop(self, func):
        ''' Set a callback to be run when this agent is stopped.
        
        :param func: The callback, which takes no arguments.
        '''
        self._on_stop = func
    
    @dbus.service.method(IFACE, in_signature='')
    def stop(self):
        if self._bindsock:
            self.__logger.info('Un-listening')
            self._bindsock.shutdown(socket.SHUT_RDWR)
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
            self.__logger.warning('Failed: {0}'.format(err))
        
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

def main():
    parser = argparse.ArgumentParser()
    subp = parser.add_subparsers(dest='action', help='action')
    parser.add_argument('--eid', type=unicode, help='This node EID')
    parser.add_argument('--keepalive', type=int, help='Keepalive time in seconds')
    parser.add_argument('--idle', type=int, help='Idle time in seconds')
    parser.add_argument('--bus-service', type=str, help='D-Bus service name')
    parser.add_argument('--tls-ca', type=str, help='Filename for CA chain')
    parser.add_argument('--tls-cert', type=str, help='Filename for X.509 certificate')
    parser.add_argument('--tls-key', type=str, help='Filename for X.509 private key')
    parser.add_argument('--tls-dhparam', type=str, help='Filename for DH parameters')
    
    parser_listen = subp.add_parser('listen', help='Listen for TCP connections')
    parser_listen.add_argument('--address', type=str, default='',
                               help='Listen name or address')
    parser_listen.add_argument('--port', type=int, default=4556,
                               help='Listen TCP port')
    
    parser_conn = subp.add_parser('connect', help='Make a TCP connection')
    parser_conn.add_argument('address', type=str, help='Host name or address')
    parser_conn.add_argument('--port', type=int, default=4556,
                             help='Host TCP port')
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.DEBUG)
    
    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)
    
    config = Config()
    
    config.bus_conn = dbus.bus.BusConnection(dbus.bus.BUS_SESSION)
    if args.bus_service:
        bus_serv = dbus.service.BusName(bus=config.bus_conn, name=args.bus_service, do_not_queue=True)
        logging.info('Registered as "{0}"'.format(bus_serv.get_name()))
    
    if True:
        config.ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        config.ssl_ctx.set_ciphers(ssl._DEFAULT_CIPHERS)
        if args.tls_ca:
            config.ssl_ctx.load_verify_locations(args.tls_ca)
        if args.tls_cert:
            config.ssl_ctx.load_cert_chain(args.tls_cert, args.tls_key)
        if args.tls_dhparam:
            config.ssl_ctx.load_dh_params(args.tls_dhparam)
    config.eid = args.eid
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
        if False:
            config.ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            config.ssl_ctx.check_hostname = True
        else:
            config.ssl_ctx.verify_mode = ssl.CERT_NONE
            config.ssl_ctx.check_hostname = False
        agent.connect(args.address, args.port)
    
    eloop = glib.MainLoop()
    agent.set_on_stop(lambda: eloop.quit())
    try:
        eloop.run()
    except KeyboardInterrupt:
        pass
    agent.stop()

if __name__ == '__main__':
    sys.exit(main())