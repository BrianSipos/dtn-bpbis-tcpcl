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
import string
import struct
import unittest
from binascii import b2a_hex
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
    '''
    # Tag 24: Encoded CBOR data item
    return cbor2.CBORTag(24, cbor2.dumps(value))


class Block(object):

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

        post_crc = cbor2.dumps(self.fields)


def randtext(sizemax=100):
    size = random.randint(0, sizemax)
    return u''.join([random.choice(string.printable) for _ in range(size)])


def randbytes(sizemax=100):
    size = random.randint(0, sizemax)
    return bytes(bytearray([random.randint(0, 255) for _ in range(size)]))


def randdtntime():
    return random.randint(-1e10, 1e10)


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

    def create_block_data(self, block_type, block_flags):
        ''' Block-type-specific data gerator.
        '''
        if block_type == 1 and block_flags & 0x0002:
            # Admin record
            admin_type = 1
            admin_data = [  # Status Report
                [  # Status info
                    randstatus(), # Reporting node received bundle
                    randstatus(), # Reporting node forwarded the bundle
                    randstatus(),  # Reporting node delivered the bundle
                    randstatus(), # Reporting node deleted the bundle
                ],
                random.randint(0, 9),  # Reason code
                randtext(),  # Source Node EID
                randtimestamp(),  # Creation timestamp
            ]
            return binaryCborTag([
                admin_type,
                admin_data,
            ])
        elif block_type == 7:
            # Previous Node
            return binaryCborTag(randtext())
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

    def create_block_random(self, block_type):
        block_flags = random.getrandbits(8)
        block = Block(
            [  # extenstion
                block_type,  # block type
                random.randint(1, 30) if block_type != 1 else 0,  # block number
                block_flags,  # block flags
                random.randint(0, 2),  # CRC type
                self.create_block_data(block_type, block_flags),  # block data
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
        blocks = []
        block = Block(
            [  # primary block
                7,  # BP version
                random.getrandbits(16),  # bundle flags
                random.randint(1, 2),  # CRC type
                randtext(),
                randtext(),
                randtext(),
                randtimestamp(),  # creation timestamp
                random.randint(0, 1e5),  # lifetime
            ],
            crc_type_ix=2,
        )
        if block.fields[1] & 0x0001:
            # Is fragment
            block.fields.append(random.randint(0, 1e4))
        if block.fields[block.crc_type_ix] != 0:
            # Has CRC
            block.fields.append(None)
            block.crc_field_ix = len(block.fields) - 1
        blocks.append(block)

        # Non-payload blocks
        for _ in range(random.randint(0, 4)):
            block_type = random.choice(self.KNOWN_BLOCK_TYPES)
            block = self.create_block_random(block_type)
            blocks.append(block)
        # Last block is payload
        if True:
            block_type = 1
            block = self.create_block_random(block_type)
            blocks.append(block)

        buf = io.BytesIO()
        buf.write(b'\xd9\xd9\xf7\x9F')
        for block in blocks:
            block.update_crc()
            cbor2.dump(block.fields, buf)
        buf.write(b'\xFF')
        buf.seek(0)
        return buf


def agent_send_bundles(agent, contact, genmode, gencount):
    ''' A glib callback to send a sequence of bundles and then shutdown the agent.

    :type agent: :py:cls:`tcpcl.agent.Agent`
    :type contact: :py:cls:`tcpcl.agent.ContactHandler`
    '''
    gen = Generator()
    if genmode == 'fullvalid':
        # Some valid bundles
        for _ in range(gencount):
            contact.send_bundle_fileobj(gen.create_valid())
    elif genmode == 'randcbor':
        # Some valid-but-random CBOR
        for _ in range(gencount):
            contact.send_bundle_fileobj(gen.create_invalid_cbor())
    elif genmode == 'randbytes':
        # Some genuine random data
        for _ in range(gencount):
            contact.send_bundle_fileobj(gen.create_invalid_random())

    def check_done():
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
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper())
    logging.debug('command args: %s', args)

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
        contact.set_on_session_start(lambda: agent_send_bundles(agent, contact, args.genmode, args.gencount))
        agent.exec_loop()

    worker_pasv = multiprocessing.Process(target=run_pasv, args=[config_pasv])
    worker_pasv.start()
    worker_actv = multiprocessing.Process(target=run_actv, args=[config_actv])
    worker_actv.start()

    worker_actv.join()
    worker_pasv.join()


if __name__ == '__main__':
    sys.exit(main())
