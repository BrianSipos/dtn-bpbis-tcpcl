'''
Implementation of a symmetric TCPCL agent.
'''

import sys
import logging
import argparse
import socket
import ssl
import glib
import dbus
import dbus.service
import uuid
from dbus.mainloop.glib import DBusGMainLoop
from scapy import packet
from tcpcl import messages

class Config(object):
    ''' Agent configuration.
    
    .. py:attribute:: eid
        The EID of this node.
    .. py:attribute:: bus_conn
        An optional D-Bus connection object to register handlers on.
    '''
    def __init__(self):
        self.eid = ''
        self.bus_conn = None
        self.keepalive_time = 0
        self.idle_time = 0
        self.tls_attempt = True
        self.tls_require = True

class Connection(object):
    ''' Optionally secured socket connection.
    
    :param sock: The unsecured socket to wrap.
    '''
    def __init__(self, sock):
        self.__logger = logging.getLogger(self.__class__.__name__)
        #: The raw socket
        self._s_notls = None
        #: Optionally secured socket
        self._s_tls = None
        
        #: listener for _s_notls socket
        self._avail_notls_id = None
        #: optional listener for _s_tls socket
        self._avail_tls_id = None
        
        self._replace_socket(sock)
    
    def is_secure(self):
        ''' Determine if TLS is established.
        
        :return: True if operating with TLS.
        '''
        return (self._s_tls is not None)
    
    def __unlisten_notls(self):
        if self._avail_notls_id is not None:
            glib.source_remove(self._avail_notls_id)
            self._avail_notls_id = None
    
    def __unlisten_tls(self):
        if self._avail_tls_id is not None:
            glib.source_remove(self._avail_tls_id)
            self._avail_tls_id = None
    
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
            self._avail_notls_id = glib.io_add_watch(self._s_notls, glib.IO_IN, self._avail_notls)
        
        return old
    
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
    
    def secure(self, ssl_ctx):
        ''' Add a TLS connection layer (if not present).
        
        :param ssl_ctx: The context to use for security.
        :type ssl_ctx: :py:class:`ssl.SSLContext`
        :raise ssl.SSLError: If the negotiation fails.
        '''
        if self._s_tls:
            return
        
        if self._from:
            self._s_tls = self._config.ssl_ctx.wrap_socket(self._s_notls,
                                                server_side=True,
                                                do_handshake_on_connect=False)
        elif self._to:
            self._s_tls = self._config.ssl_ctx.wrap_socket(self._s_notls,
                                                server_hostname=self._to[0],
                                                do_handshake_on_connect=False)
        else:
            raise ValueError('Neither from nor to')
        
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
        
        self._avail_tls_id = glib.io_add_watch(self._s_tls, glib.IO_IN, self._avail_tls)
    
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
    
    def _avail_notls(self, *args, **kwargs):
        ''' Callback for new :py:obj:`_s_notls` data. '''
        if self._s_tls is not None:
            return True
        
        rx_data = self._s_notls.recv(1024)
        if len(rx_data) == 0:
            self.close()
            return False
        
        self._rx_proxy(rx_data)
        return True
    
    def _avail_tls(self, *args, **kwargs):
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
        self.recv_data(data)
    
    def recv_data(self, data):
        ''' Handler for received blocks of data.
        
        :param data: The received data.
        :type data: str
        '''
        pass
    
    def send_data(self, data):
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
    
class HandlerBase(Connection):
    ''' Individual contact handler. '''
    
    def __init__(self, config, sock, fromaddr=None, toaddr=None):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self._config = config
        self._keepalive_time = 0
        self._idle_time = 0
        
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
        Connection.__init__(self, sock)
    
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
    
    def recv_data(self, data):
        ''' Attempt to extract a message from the current read buffer.
        '''
        self._idle_reset()
        if self._in_conn:
            msgcls = messages.MessageHead
        else:
            msgcls = messages.Contact
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
        
        if isinstance(pkt, messages.Contact):
            if pkt.magic != messages.Contact.MAGIC_HEAD:
                raise ValueError('Contact header with bad magic: {0}'.format(pkt.magic.encode('hex')))
            self._head_peer = pkt
            self._in_conn = True
            self.merge_contact()
            
            # Client initiates STARTTLS
            if not self.is_server() and not self.is_secure() and self._config.tls_attempt:
                self.send_message(messages.MessageHead()/messages.StartTls())
        else:
            # Some payloads are empty and scapy will not construct them
            msgcls = pkt.guess_payload_class('')
            if msgcls == messages.Shutdown:
                # Send a reply (if not the initiator)
                if not self._wait_shutdown:
                    self.do_shutdown()
                
                self.close()
            
            elif msgcls == messages.Keepalive:
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
                        self.send_reject(messages.RejectMsg.REASON_UNSUPPORTED, pkt)
            
            else:
                # Bad RX message
                self.send_reject(messages.RejectMsg.REASON_UNKNOWN, pkt)
    
    def merge_contact(self):
        ''' Combine local and peer contact headers to contact configuration.
        '''
        self.__logger.debug('Contact negotiation')
        self._keepalive_time = min(self._head_this.keepalive, self._head_peer.keepalive)
        self._idle_time = self._config.idle_time
        self._keepalive_reset()
        self._idle_reset()
        
        
    
    def send_message(self, pkt):
        ''' Send a full message (or contact header).
        
        :param pkt: The message packet to send.
        '''
        self.__logger.info('TX: {0}'.format(repr(pkt)))
        pkt_data = str(pkt)
        self.__logger.debug('TX data: {0}'.format(pkt_data.encode('hex')))
        self.send_data(pkt_data)
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
    
    def send_contact_header(self):
        pkt = messages.Contact(flags='ENA_LENGTH+ENA_REFUSE+ENA_ACK',
                               keepalive=self._config.keepalive_time,
                               eid_data=self._config.eid.encode('utf8'))
        self.send_message(pkt)
        return pkt
    
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
        self._head_this = self.send_contact_header()

class HandlerProxy(HandlerBase, dbus.service.Object):
    ''' A proxy object for HandlerBase objects.
    
    :param handler: The handler to manipulate.
    :type handle: :py:cls:`HandlerBase`
    '''
    def __init__(self, handler, **kwargs):
        self._hdl = handler
        self._bundles = {}
        dbus.service.Object.__init__(self, **kwargs)
    
    IFACE = 'com.rkf_eng.dtn.tcpcl.Handler'
    
    @dbus.service.method(IFACE, in_signature='ay', out_signature='s')
    def send_bundle(self, data):
        bid = uuid.uuid4()
        self._bundles[bid] = data
        glib.idle_add(self._process_queue, bid)
        return str(bid)
    
    @dbus.service.signal(IFACE, signature='s')
    def bundle_started(self, bid):
        pass
    
    def _process_queue(self, bid):
        print 'processing', bid
        self.bundle_started(str(bid))

class Agent(object):
    ''' Overall agent behavior. '''
    
    def __init__(self, config):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self._config = config
        
        self._bindsock = None
        self._obj_id = 0
    
    def __del__(self):
        self.stop()
    
    def stop(self):
        if self._bindsock:
            self.__logger.info('Un-listening')
            self._bindsock.shutdown(socket.SHUT_RDWR)
            self._bindsock = None
    
    def _get_obj_path(self):
        hdl_id = self._obj_id
        self._obj_id += 1
        return '/com/rkf_eng/dtn/tcpcl/Handler{0}'.format(hdl_id)
    
    def _bind_handler(self, hdl):
        if not self._config.bus_conn:
            return
        
        path = self._get_obj_path()
        self._prox = HandlerProxy(hdl, conn=self._config.bus_conn, object_path=path)
        self.__logger.info('New handler at "{0}"'.format(path))
    
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
        hdl = HandlerBase(self._config, newsock, fromaddr=fromaddr)
        self._bind_handler(hdl)
        
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
        
        hdl = HandlerBase(self._config, sock, toaddr=(address,port))
        self._bind_handler(hdl)
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
            ctx.load_dh_params(args.tls_dhparam)
    config.eid = args.eid
    if args.keepalive:
        config.keepalive_time = args.keepalive
    if args.idle:
        config.idle_time = args.idle
    else:
        config.idle_time = 2 * config.keepalive_time
    
    agent = Agent(config)
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
    try:
        eloop.run()
    except KeyboardInterrupt:
        pass
    agent.stop()

if __name__ == '__main__':
    sys.exit(main())