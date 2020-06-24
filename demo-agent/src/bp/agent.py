'''
Implementation of a symmetric BPv6 agent.
'''
import argparse
import datetime
import logging
import sys
import dbus.service
from gi.repository import GLib as glib
import cbor2
#from multiprocessing import Process
#import tcpcl.agent
from .encoding import (
    DtnTimeField, Timestamp,
    Bundle, AbstractBlock, PrimaryBlock, CanonicalBlock, AdminRecord,
    StatusReport, StatusInfoArray, StatusInfo
)

LOGGER = logging.getLogger(__name__)


class BundleContainer(object):
    ''' A high-level representation of a bundle.
    This includes logical constraints not present in :py:cls:`encoding.Bundle`
    data handling class.
    '''

    def __init__(self, bundle=None):
        if bundle is None:
            bundle = Bundle()
        self.bundle = bundle
        # Map from block number to single Block
        self._block_num = {}
        # Map from block type to list of Blocks
        self._block_type = {}

        self.reload()

    def block_num(self, num):
        return self._block_num[num]

    def block_type(self, type_code):
        return self._block_type[type_code]

    def reload(self):
        ''' Reload derived info from the bundle.
        '''
        if self.bundle is None:
            return

        block_num = {}
        block_type = {}
        if self.bundle.payload is not None:
            block_num[0] = self.bundle.payload
        for blk in self.bundle.blocks:
            blk_num = blk.getfieldval('block_num')
            if blk_num is not None:
                if blk_num in block_num:
                    raise RuntimeError('Duplicate block_num value')
                block_num[blk_num] = blk

            blk_type = blk.getfieldval('type_code')
            if blk_type not in block_type:
                block_type[blk_type] = []
            block_type[blk_type].append(blk)

        self._block_num = block_num
        self._block_type = block_type

    def fix_block_num(self):
        ''' Assign unique block numbers where needed.
        '''
        last_num = 1
        for blk in self.bundle.blocks:
            if blk.getfieldval('block_num') is None:
                if blk.getfieldval('type_code') == 1:
                    set_num = 1
                else:
                    while True:
                        last_num += 1
                        if last_num not in self._block_num:
                            set_num = last_num
                            break
                blk.overloaded_fields['block_num'] = set_num

    def do_report_reception(self):
        return (
            self.bundle.primary.report_to != 'dtn:none'
            and self.bundle.primary.bundle_flags & PrimaryBlock.Flag.REQ_RECEPTION_REPORT
        )

    def create_report_reception(self, timestamp):
        status_ts = bool(self.bundle.primary.bundle_flags & PrimaryBlock.Flag.REQ_STATUS_TIME)

        report = StatusReport(
            status=StatusInfoArray(
                received=StatusInfo(
                    status=True,
                    at=(timestamp.time if status_ts else None),
                ),
            ),
            reason_code=0,
            subj_source=self.bundle.primary.source,
            subj_ts=self.bundle.primary.create_ts,
        )

        reply = BundleContainer()
        reply.bundle.primary = PrimaryBlock(
            bundle_flags=PrimaryBlock.Flag.PAYLOAD_ADMIN,
            destination=self.bundle.primary.report_to,
            source=self.bundle.primary.destination,
            create_ts=timestamp,
            crc_type=AbstractBlock.CrcType.CRC32,
        )
        reply.bundle.blocks = [
            CanonicalBlock(
                type_code=1,
                crc_type=AbstractBlock.CrcType.CRC32,
            ) / AdminRecord(
            ) / report,
        ]
        return reply


class Config(object):
    ''' Agent configuration.

    .. py:attribute:: enable_test
        A set of test-mode behaviors to enable.
    .. py:attribute:: bus_conn
        The D-Bus connection object to register handlers on.
    .. py:attribute:: own_eid
        This agent's EID to respond to.
    .. py:attribute:: route_table
        A map from destination EID to next-hop Node ID.
    '''

    def __init__(self):
        self.enable_test = set()
        self.bus_conn = dbus.bus.BusConnection(dbus.bus.BUS_SESSION)
        self.own_eid = u''
        self.route_table = {}


class ClSession(object):
    ''' Convergence layer session keeping.
    '''

    def __init__(self):
        self.serv_name = None
        self.obj_path = None

        self.sess_params = None
        self.nodeid = None
        self.sess_obj = None


class Timestamper(object):
    ''' Generate a unique Timestamp with sequence state.
    '''

    def __init__(self):
        self._time = None
        self._seqno = 0

    def __call__(self):
        ''' Generate the next timestamp.
        '''
        now_time = DtnTimeField.datetime_to_dtntime(
            datetime.datetime.utcnow().replace(
                microsecond=0,
                tzinfo=datetime.timezone.utc,
            )
        )
        if self._time is not None and now_time == self._time:
            self._seqno += 1
        else:
            self._time = now_time
            self._seqno = 0

        return Timestamp(
            time=self._time,
            seqno=self._seqno
        )


class Agent(dbus.service.Object):
    ''' Overall agent behavior.

    :param config: The agent configuration object.
    :type config: :py:class:`Config`
    :param bus_kwargs: Arguments to :py:class:`dbus.service.Object` constructor.
        If not provided the default dbus configuration is used.
    :type bus_kwargs: dict or None
    '''

    DBUS_IFACE = 'org.ietf.dtn.bp.Agent'

    def __init__(self, config, bus_kwargs=None):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self._config = config
        self._on_stop = None
        #: Set when shutdown() is called and waiting on sessions
        self._in_shutdown = False

        self.route_table = {
            'dtn://client/': ('localhost', 4556),
            'dtn://server/': ('localhost', 4556),
        }

        self.timestamp = Timestamper()

        self._cl_agent_obj = None
        # Map for CL connection DBus objects
        # Map from (serv_name, obj_path) to ClSession
        self._cl_sess_objs = {}
        # Map from peer Node ID to ClSession
        self._cl_peer_nodeids = {}

        if bus_kwargs is None:
            bus_kwargs = dict(
                conn=config.bus_conn,
                object_path='/org/ietf/dtn/bp/Agent'
            )
        dbus.service.Object.__init__(self, **bus_kwargs)

    def __del__(self):
        self.stop()

    def set_on_stop(self, func):
        ''' Set a callback to be run when this agent is stopped.

        :param func: The callback, which takes no arguments.
        '''
        self._on_stop = func

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='b')
    def shutdown(self):
        ''' Gracefully terminate all open sessions.
        Once the sessions are closed then the agent may stop.

        :return: True if the agent is stopped immediately or
            False if a wait is needed.
        '''
        self.__logger.info('Shutting down agent')
        self._in_shutdown = True
        self.stop()
        return True

    @dbus.service.method(DBUS_IFACE, in_signature='')
    def stop(self):
        ''' Immediately stop the agent and disconnect any sessions. '''

        if self._on_stop:
            self._on_stop()

    def exec_loop(self):
        ''' Run this agent in an event loop.
        The on_stop callback is replaced to quit the event loop.
        '''
        eloop = glib.MainLoop()
        self.set_on_stop(eloop.quit)
        self.__logger.info('Starting event loop')
        try:
            eloop.run()
        except KeyboardInterrupt:
            if not self.shutdown():
                # wait for graceful shutdown
                eloop.run()

    def _cl_conn_attach(self, servname):
        ''' Get a function to attach to new connection object.
        '''

        def func(conn_path):
            conn_obj = self._config.bus_conn.get_object(servname, conn_path)
            LOGGER.debug('Attaching to CL object %s', conn_path)
            cl_sess = ClSession()
            cl_sess.serv_name = servname
            cl_sess.obj_path = conn_path
            cl_sess.sess_obj = conn_obj
            self._cl_sess_objs[(servname, conn_path)] = cl_sess

            def handle_recv_bundle_finish(bid, _length, result):
                if result != 'success':
                    return
                data = conn_obj.recv_bundle_pop_data(bid)
                data = dbus.ByteArray(data)
                print('data', cbor2.loads(data))
                self._cl_recv_bundle_finish(data)

            conn_obj.connect_to_signal('recv_bundle_finished', handle_recv_bundle_finish)

            def handle_state_change(state):
                if state == 'established':
                    params = conn_obj.get_session_parameters()
                    cl_sess = self._cl_sess_objs[(servname, conn_path)]
                    cl_sess.nodeid = str(params['peer_nodeid'])
                    cl_sess.sess_params = params
                    LOGGER.debug('Session established with %s', cl_sess.nodeid)
                    self._cl_peer_nodeids[cl_sess.nodeid] = cl_sess

            state = conn_obj.get_session_state()
            if state != 'established':
                conn_obj.connect_to_signal('session_state_changed', handle_state_change)
            handle_state_change(state)

        return func

    def _cl_conn_detach(self, servname):
        ''' Get a function to detach from a removed connection object.
        '''

        def func(conn_path):
            cl_sess = self._cl_sess_objs[(servname, conn_path)]
            del self._cl_sess_objs[(cl_sess.serv_name, cl_sess.obj_path)]
            del self._cl_peer_nodeids[cl_sess.nodeid]

        return func

    def _cl_recv_bundle_finish(self, data):
        ''' Handle a new received bundle from a CL.
        '''
        print('Saw bundle data len {}'.format(len(data)))
        ctr = BundleContainer(Bundle(data))
        self.recv_bundle(ctr)

    def _add_cl_session(self, cl_sess):
        self._cl_sess_objs[(cl_sess.serv_name, cl_sess.obj_path)] = cl_sess
        self._cl_peer_nodeids[cl_sess.nodeid] = cl_sess

    def _get_session_for(self, nodeid):
        self.__logger.info('Getting session for: %s', nodeid)
        if nodeid in self._cl_peer_nodeids:
            self.__logger.info('Existing to %s', nodeid)
            cl_sess = self._cl_peer_nodeids[nodeid]
        else:
            (address, port) = self.route_table[nodeid]
            self.__logger.info('Connecting new session to %s:%d', address, port)
            serv_name = self._cl_agent_obj.bus_name
            sess_path = self._cl_agent_obj.connect(address, port)
            sess_obj = self._config.bus_conn.get_object(serv_name, sess_path)

            cl_sess = ClSession()
            cl_sess.serv_name = serv_name
            cl_sess.obj_path = sess_path
            cl_sess.nodeid = nodeid
            cl_sess.sess_obj = sess_obj
            self._add_cl_session(cl_sess)
        return cl_sess

    def recv_bundle(self, ctr):
        ''' Perform agent handling of a received bundle.

        :param ctr: The bundle container just recieved.
        :type ctr: :py:cls:`BundleContainer`
        '''
        LOGGER.info('Received bundle\n%s', ctr.bundle.show(dump=True))
        LOGGER.debug('CRC invalid %s', ctr.bundle.check_all_crc())

        if ctr.do_report_reception():
            self.send_bundle(ctr.create_report_reception(self.timestamp()))

    def send_bundle(self, ctr):
        ''' Perform agent handling to send a bundle.
        Part of this is to update final CRCs on all blocks and
        assign block numbers.

        :param ctr: The bundle container to send.
        :type ctr: :py:cls:`BundleContainer`
        '''
        dest_eid = str(ctr.bundle.primary.destination)
        cl_sess = self._get_session_for(dest_eid)

        ctr.fix_block_num()
        ctr.bundle.update_all_crc()
        LOGGER.info('Sending bundle\n%s', ctr.bundle.show(dump=True))

        cl_sess.sess_obj.send_bundle_data(dbus.ByteArray(bytes(ctr.bundle)))

    @dbus.service.method(DBUS_IFACE, in_signature='s', out_signature='')
    def cl_attach(self, servname):
        ''' Listen to sessions and bundles from a CL agent.

        :param str servname: The DBus service name to listen from.
        '''
        LOGGER.debug('Attaching to CL service {}'.format(servname))
        agent_path = '/org/ietf/dtn/tcpcl/Agent'
        agent_obj = self._config.bus_conn.get_object(servname, agent_path)
        self._cl_agent_obj = agent_obj

        attach_func = self._cl_conn_attach(servname)
        detach_func = self._cl_conn_detach(servname)
        agent_obj.connect_to_signal('connection_opened', attach_func)
        agent_obj.connect_to_signal('connection_closed', detach_func)
        for conn_path in agent_obj.get_connections():
            attach_func(conn_path)

    @dbus.service.method(DBUS_IFACE, in_signature='s', out_signature='')
    def ping(self, nodeid):
        ''' Ping via TCPCL and an admin record.

        :param str servname: The DBus service name to listen from.
        '''

        cts = self.timestamp()

        ctr = BundleContainer()
        ctr.bundle.primary = PrimaryBlock(
            bundle_flags=(PrimaryBlock.Flag.REQ_RECEPTION_REPORT | PrimaryBlock.Flag.REQ_STATUS_TIME),
            destination=nodeid,
            source='dtn://client/',
            report_to='dtn://client/',
            create_ts=cts,
            crc_type=AbstractBlock.CrcType.CRC32,
        )
        ctr.bundle.blocks = [
            CanonicalBlock(
                type_code=1,
                crc_type=AbstractBlock.CrcType.CRC32,
            ) / AdminRecord(
                type_code=3
            ),
        ]

        self.send_bundle(ctr)


def str2bool(val):
    ''' Require an option value to be boolean text.
    '''
    if val.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    if val.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    raise argparse.ArgumentTypeError('Boolean value expected')


def main():
    ''' Agent command entry point. '''
    from dbus.mainloop.glib import DBusGMainLoop

    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    parser.add_argument('--enable-test', type=str, default=[],
                        action='append', choices=['private_extensions'],
                        help='Names of test modes enabled')
    parser.add_argument('--bus-service', type=str,
                        help='D-Bus service name')
    parser.add_argument('--cl-service', type=str,
                        help='DBus service name')
    parser.add_argument('--eloop', type=str2bool, default=True,
                        help='If enabled, waits in an event loop.')
    subp = parser.add_subparsers(dest='action', help='action')

    parser_ping = subp.add_parser('ping',
                                  help='Send an admin record')
    parser_ping.add_argument('nodeid', type=str)

    args = parser.parse_args()
    logging.basicConfig(level=args.log_level.upper())
    logging.debug('command args: %s', args)

    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)

    config = Config()

    config.enable_test = frozenset(args.enable_test)
    if args.bus_service:
        bus_serv = dbus.service.BusName(
            bus=config.bus_conn, name=args.bus_service, do_not_queue=True)
        logging.info('Registered as "%s"', bus_serv.get_name())

    agent = Agent(config)
    if args.cl_service:
        agent.cl_attach(args.cl_service)
    if args.action == 'ping':
        agent.ping(args.nodeid)

    if args.eloop:
        agent.exec_loop()


if __name__ == '__main__':
    sys.exit(main())
