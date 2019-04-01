#!/usr/bin/python3
''' A dummy bundle data generator.
'''
import sys
import argparse
import logging
import cbor2
import crcmod
import random
import string
import struct
import unittest
from binascii import b2a_hex

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


# Type-specific data generation
def datagen(block_type, block_flags):
    if block_type == 1 and block_flags & 0x0002:
        # Admin record
        admin_type = 1
        admin_data = [  # Status Report
            [  # Status info
                [  # Reporting node received bundle
                    True,
                    randdtntime(),
                ],
                [  # Reporting node forwarded the bundle
                    False,
                ],
                [  # Reporting node delivered the bundle
                    False,
                    randdtntime(),
                ],
                [  # Reporting node deleted the bundle
                    False,
                ],
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

    return cbor2.dumps(randbytes(10))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    parser.add_argument('outfile', type=str)
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper())
    logging.debug('command args: %s', args)

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
    for _ in range(10):
        block_type = random.randint(2, 10)
        block_flags = random.getrandbits(8)
        block = Block(
            [  # extenstion
                block_type,  # block type
                random.randint(1, 30),  # block number
                block_flags,  # block flags
                random.randint(0, 2),  # CRC type
                datagen(block_type, block_flags),  # block data
            ],
            crc_type_ix=3
        )
        if block.fields[block.crc_type_ix] != 0:
            # Has CRC
            block.fields.append(None)
            block.crc_field_ix = len(block.fields) - 1
        blocks.append(block)
    # Last block is payload
    if True:
        block_type = 1
        block_flags = random.getrandbits(8)
        block = Block(
            [  # extenstion
                block_type,  # block type
                random.randint(1, 30),  # block number
                block_flags,  # block flags
                random.randint(0, 2),  # CRC type
                datagen(block_type, block_flags),  # block data
            ],
            crc_type_ix=3
        )
        if block.fields[block.crc_type_ix] != 0:
            # Has CRC
            block.fields.append(None)
            block.crc_field_ix = len(block.fields) - 1
        blocks.append(block)

    with open(args.outfile, 'wb') as outfile:
        outfile.write(b'\x9F')
        for block in blocks:
            block.update_crc()
            cbor2.dump(block.fields, outfile)
        outfile.write(b'\xFF')

    with open(args.outfile, 'rb') as outfile:
        import io
        import pprint

        buf = io.StringIO()
        pprint.PrettyPrinter(stream=buf).pprint(cbor2.load(outfile))
        LOGGER.debug('Content: %s', buf.getvalue())


class TestBundleGen(unittest.TestCase):

    def testCrc16Itu(self):
        # Test from <http://reveng.sourceforge.net/crc-catalogue/16.htm#crc.cat.crc-16-ibm-sdlc>
        self.assertEqual(0x906e, CRC_DEFN[1]['func'](b'123456789'))

    def testCrc32C(self):
        # Test from <http://reveng.sourceforge.net/crc-catalogue/17plus.htm#crc.cat.crc-32c>
        self.assertEqual(0xe3069283, CRC_DEFN[2]['func'](b'123456789'))


if __name__ == '__main__':
    sys.exit(main())
