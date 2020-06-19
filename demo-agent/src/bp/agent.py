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
from . import encoding

LOGGER = logging.getLogger(__name__)


class BundleContainer(object):
    ''' A high-level representation of a bundle.
    This includes logical constraints not present in :py:cls:`encoding.Bundle`
    data handling class.
    '''

    def __init__(self, bundle=None):
        if bundle is None:
            bundle = encoding.Bundle()
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
        for blk in enumerate(self.bundle.blocks):
            blk_num = blk.block_num
            if blk_num in block_num:
                raise RuntimeError('Duplicate block_num value')
            block_num[blk_num] = blk

            blk_type = blk.type_code
            if blk_type not in block_type:
                block_type[blk_type] = []
            block_type[blk_type].append(blk)

#        pyld = block_type.get(1, [])
#        if len(pyld) != 1:
#            raise RuntimeError('Not exactly one payload block')
#        if pyld[0].block_num != 1:
#            raise RuntimeError('Payload is not block number 1')

        self._block_num = block_num
        self._block_type = block_type


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

    @dbus.service.method(DBUS_IFACE, in_signature='ssi', out_signature='')
    def ping(self, servname, address, port):
        ''' Ping via TCPCL and an admin record.

        '''
        agent_path = '/org/ietf/dtn/tcpcl/Agent'
        agent_obj = self._config.bus_conn.get_object(servname, agent_path)
        self.__logger.info('Connecting')
        sess_path = agent_obj.connect(address, port)
        sess_obj = self._config.bus_conn.get_object(servname, sess_path)

        bdl = BundleContainer()
        bdl.bundle.primary = encoding.PrimaryBlock(
            bundle_flags=encoding.PrimaryBlock.Flag.PAYLOAD_IS_ADMIN,
            destination='dtn:server',
            source='dtn:client',
            creation_timestamp=[datetime.datetime.utcnow(), 0],
            crc_type=2,
        )
        bdl.bundle.blocks = [
            encoding.CanonicalBlock(
                block_num=2,
            ) / encoding.HopCountBlockData(limit=5, count=0),
            encoding.CanonicalBlock(
                type_code=1,
                block_num=1,
                crc_type=2,
                data=cbor2.dumps([
                    1,
                    ['hi', 3]
                ]),
            ),
        ]
        bdl.bundle.update_all_crc()
        bdl.bundle.show()
        print('CBOR', bdl.bundle.build())

        sess_obj.send_bundle_data(dbus.ByteArray(bytes(bdl.bundle)))
        sess_obj.terminate(0)


def main(*argv):
    ''' Agent command entry point. '''
    from dbus.mainloop.glib import DBusGMainLoop

    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    parser.add_argument('--enable-test', type=str, default=[],
                        action='append', choices=['private_extensions'],
                        help='Names of test modes enabled')
    parser.add_argument('--bus-service', type=str,
                        help='D-Bus service name')

    args = parser.parse_args(argv[1:])
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
    agent.ping('dtn.tcpcl.Client', 'localhost', 4556)

    agent.exec_loop()


if __name__ == '__main__':
    sys.exit(main(*sys.argv))
