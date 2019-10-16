#!/usr/bin/python3
''' A dummy bundle data generator.
'''
import sys
import argparse
import logging
import cbor2
import crcmod
import io
import random
import shutil
import string
import struct
import unittest
from gi.repository import GLib as glib

LOGGER = logging.getLogger(__name__)

CRC_DEFN = {
    1: {  # BPv7 CRC-16 X.25
        'func': crcmod.predefined.mkPredefinedCrcFun('x-25'),
        'encode': lambda val: struct.pack('>H', val)
    },
    2: {  # BPv7 CRC-32 Castagnoli
        'func': crcmod.predefined.mkPredefinedCrcFun('crc-32c'),
        'encode': lambda val: struct.pack('>L', val)
    },
}


class TestBundleGen(unittest.TestCase):

    def testCrc16Itu(self):
        # Test from <http://reveng.sourceforge.net/crc-catalogue/16.htm#crc.cat.crc-16-ibm-sdlc>
        self.assertEqual(0x906e, CRC_DEFN[1]['func'](b'123456789'))

    def testCrc32C(self):
        # Test from <http://reveng.sourceforge.net/crc-catalogue/17plus.htm#crc.cat.crc-32c>
        self.assertEqual(0xe3069283, CRC_DEFN[2]['func'](b'123456789'))


def binaryCborTag(value):
    ''' Encode CBOR as bytestring and tag the item.

    :param value: The CBOR item to encode.
    :return: The binary-enveloped item.
    '''
    # Tag 24: Encoded CBOR data item
    return cbor2.CBORTag(24, cbor2.dumps(value))


class Block(object):
    ''' Represent an abstract block with CRC fields.
    '''

    def __init__(self, fields, crc_type_ix=None, crc_field_ix=None):
        self.fields = fields
        self.crc_type_ix = crc_type_ix
        self.crc_field_ix = crc_field_ix

    def update_crc(self):
        if self.crc_type_ix is None or self.crc_field_ix is None:
            return
        defn = CRC_DEFN[self.fields[self.crc_type_ix]]

        self.fields[self.crc_field_ix] = defn['encode'](0)
        pre_crc = cbor2.dumps(self.fields)
        crc_int = defn['func'](pre_crc)
        crc_value = defn['encode'](crc_int)
        self.fields[self.crc_field_ix] = crc_value


def randtext(sizemax=100):
    size = random.randint(0, sizemax)
    return u''.join([random.choice(string.printable) for _ in range(size)])


def randbytes(sizemax=100):
    size = random.randint(0, sizemax)
    return bytes(bytearray([random.randint(0, 255) for _ in range(size)]))


def randdtntime():
    return random.randint(0, 1e10)


def randeid():
    scheme = random.choice([1, 2])
    if scheme == 1:
        if random.uniform(0, 0) < 0.2:
            ssp = 0
        else:
            ssp = randtext()
    elif scheme == 2:
        ssp = [random.randint(0, 2 ** 15), random.randint(0, 2 ** 15)]
    return [scheme, ssp]


def randtimestamp():
    return [randdtntime(), random.randint(0, 1e3)]


def randstatus():
    result = []
    result.append(random.choice([False, True]))
    if random.randint(0, 1):
        result.append(randdtntime())
    return result


def randcboritem(maxdepth=10):
    direct_types = [None, bool, int, float, bytes, str]
    contain_types = [list, dict]

    if maxdepth == 0:
        possible_types = direct_types
    else:
        possible_types = direct_types + contain_types

    itemtype = random.choice(possible_types)

    if itemtype is None:
        return None
    elif itemtype is bool:
        return random.choice([False, True])
    elif itemtype is int:
        return random.randint(-1e3, 1e3)
    elif itemtype is float:
        return random.uniform(-1e3, 1e3)
    elif itemtype is bytes:
        return randbytes()
    elif itemtype is str:
        return randtext()
    elif itemtype is list:
        size = random.randint(0, 10)
        return [randcboritem(maxdepth - 1) for _ in range(size)]
    elif itemtype is dict:
        size = random.randint(0, 10)
        return dict([
            (randtext(8), randcboritem(maxdepth - 1))
            for _ in range(size)
        ])


class Generator(object):
    ''' A 'bundle' data generator.
    '''

    KNOWN_BLOCK_TYPES = (7, 8, 9)

    def create_block_data(self, block_type, block_flags, bundle_flags):
        ''' Block-type-specific data gerator.
        '''
        if block_type == 1 and bundle_flags & 0x0002:
            # Admin record
            admin_type = 1
            admin_data = [  # Status Report
                [  # Status info
                    randstatus(),  # Reporting node received bundle
                    randstatus(),  # Reporting node forwarded the bundle
                    randstatus(),  # Reporting node delivered the bundle
                    randstatus(),  # Reporting node deleted the bundle
                ],
                random.randint(0, 9),  # Reason code
                randeid(),  # Source Node EID
                randtimestamp(),  # Creation timestamp
            ]
            return binaryCborTag([
                admin_type,
                admin_data,
            ])
        elif block_type == 7:
            # Previous Node
            return binaryCborTag(randeid())
        elif block_type == 8:
            # Bundle Age
            return binaryCborTag(random.randint(0, 1e10))
        elif block_type == 9:
            # Hop Count
            return binaryCborTag([
                random.randint(0, 1e1),  # limit
                random.randint(0, 1e1),  # current
            ])

        return cbor2.dumps(randcboritem())

    def create_block_random(self, block_type, bundle_flags, unused_blocknum):
        block_flags = random.getrandbits(8)
        block_num = random.choice(tuple(unused_blocknum))
        unused_blocknum.remove(block_num)
        block = Block(
            [  # extenstion
                block_type,  # block type
                block_num,  # block number
                block_flags,  # block flags
                random.randint(0, 2),  # CRC type
                self.create_block_data(block_type, block_flags, bundle_flags),  # block data
            ],
            crc_type_ix=3
        )
        if block.fields[block.crc_type_ix] != 0:
            # Has CRC
            block.fields.append(None)
            block.crc_field_ix = len(block.fields) - 1
        return block

    def create_invalid_random(self):
        ''' Generate a purely random data.

        :return: A single bundle file.
        :rtype: file-like
        '''
        return io.BytesIO(randbytes(random.randint(10, 100)))

    def create_invalid_cbor(self):
        ''' Generate a valid-CBOR content which is not really a bundle.

        :return: A single bundle file.
        :rtype: file-like
        '''
        return io.BytesIO(cbor2.dumps(randcboritem()))

    def create_valid(self):
        ''' Generate a random, but structurally valid, encoded bundle.

        :return: A single bundle file.
        :rtype: file-like
        '''
        bundle_flags = random.getrandbits(16)
        blocks = []
        block = Block(
            [  # primary block
                7,  # BP version
                bundle_flags,  # bundle flags
                random.randint(1, 2),  # CRC type
                randeid(),
                randeid(),
                randeid(),
                randtimestamp(),  # creation timestamp
                random.randint(0, 1e5),  # lifetime
            ],
            crc_type_ix=2,
        )
        if block.fields[1] & 0x0001:
            # Is fragment
            block.fields.append(random.randint(0, 1e4))  # fragment offset
            block.fields.append(random.randint(0, 1e4))  # total application data unit length
        if block.fields[block.crc_type_ix] != 0:
            # Has CRC
            block.fields.append(None)
            block.crc_field_ix = len(block.fields) - 1
        blocks.append(block)

        unused_blocknum = set(range(2, 30))
        # Non-payload blocks
        for _ in range(random.randint(0, 4)):
            block_type = random.choice(self.KNOWN_BLOCK_TYPES)
            block = self.create_block_random(block_type, bundle_flags, unused_blocknum)
            blocks.append(block)
        # Last block is payload
        if True:
            block_type = 1
            block = self.create_block_random(block_type, bundle_flags, {1})
            blocks.append(block)

        buf = io.BytesIO()
        if True:
            # Self-describe CBOR Tag
            buf.write(b'\xd9\xd9\xf7')
        buf.write(b'\x9F')
        for block in blocks:
            block.update_crc()
            cbor2.dump(block.fields, buf)
        buf.write(b'\xFF')
        buf.seek(0)
        return buf


def bundle_iterable(genmode, gencount):
    ''' A generator to yield encoded bundles as file-like objects.
    '''
    gen = Generator()
    if genmode == 'fullvalid':
        # Some valid bundles
        func = gen.create_valid
    elif genmode == 'randcbor':
        # Some valid-but-random CBOR
        func = gen.create_invalid_cbor
    elif genmode == 'randbytes':
        # Some genuine random data
        func = gen.create_invalid_random

    for _ in range(gencount):
        yield func()


def agent_send_bundles(agent, contact, iterable):
    ''' A glib callback to send a sequence of bundles and then shutdown the agent.

    :type agent: :py:class:`tcpcl.agent.Agent`
    :type contact: :py:class:`tcpcl.agent.ContactHandler`
    :param iterable: An iterable object which produces file-like bundles.
    '''
    for bundle in iterable:
        contact.send_bundle_fileobj(bundle)

    def check_done():
        ''' Periodic callback to exit the event loop once the session is idle.
        '''
        LOGGER.debug('Checking idle status...')
        if contact.is_sess_idle():
            contact.terminate()
            return False
        # keep checking
        return True

    glib.timeout_add(100, check_done)

    return False


def main():
    import multiprocessing
    from dbus.mainloop.glib import DBusGMainLoop
    import tcpcl.agent

    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    parser.add_argument('genmode',
                        choices=('fullvalid', 'randcbor', 'randbytes'),
                        help='Type of "bundle" to generate.')
    parser.add_argument('gencount', type=int,
                        help='Number of bundles to transfer.')
    parser.add_argument('--to-file', type=str, default=None,
                        metavar='NAMEPREFIX',
                        help='If this option is provided the bundles are written to file instead of sent over network.')
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper())
    logging.debug('command args: %s', args)

    if args.to_file:
        for (ix, bundle) in enumerate(bundle_iterable(args.genmode, args.gencount)):
            file_name = '{0}{1}.cbor'.format(args.to_file, ix)
            LOGGER.info('Writing bundle to %s', file_name)
            with open(file_name, 'wb') as outfile:
                shutil.copyfileobj(bundle, outfile)
        return 0

    # (address,port) combo to use TCPCL on
    address = ('localhost', 4556)

    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)

    config_pasv = tcpcl.agent.Config()
    config_pasv.stop_on_close = True

    def run_pasv(config):
        agent = tcpcl.agent.Agent(config)
        agent.listen(*address)
        agent.exec_loop()

    config_actv = tcpcl.agent.Config()
    config_actv.stop_on_close = True

    def run_actv(config):
        agent = tcpcl.agent.Agent(config)
        path = agent.connect(*address)
        contact = agent.handler_for_path(path)
        contact.set_on_session_start(lambda: agent_send_bundles(agent, contact, bundle_iterable(args.genmode, args.gencount)))
        agent.exec_loop()

    worker_pasv = multiprocessing.Process(target=run_pasv, args=[config_pasv])
    worker_pasv.start()
    worker_actv = multiprocessing.Process(target=run_actv, args=[config_actv])
    worker_actv.start()

    worker_actv.join()
    worker_pasv.join()


if __name__ == '__main__':
    sys.exit(main())
