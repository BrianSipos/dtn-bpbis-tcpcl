import sys
import argparse
import logging
import cbor2
import crcmod
import struct
from binascii import b2a_hex

CRC_DEFN = {
    1: {  # BPv7 CRC-16
        'func': crcmod.predefined.mkPredefinedCrcFun('x-25'),
        'xor': 0xFFFF,
        'encode': lambda val: struct.pack('>H', val)
    },
    2: {  # BPv7 CRC-32
        'func': crcmod.predefined.mkPredefinedCrcFun('crc32'),
        'xor': 0xFFFFFFFF,
        'encode': lambda val: struct.pack('>L', val)
    },
}


class FixedUInt16(object):
    ''' A fixed-width 16-bit unsigned integer.
    
    :param subval: The value to be encoded.
    '''

    def __init__(self, subval):
        self.subval = subval


class FixedUInt32(object):
    ''' A fixed-width 32-bit unsigned integer.
    
    :param subval: The value to be encoded.
    '''

    def __init__(self, subval):
        self.subval = subval


class BinaryEncodedCbor(object):
    ''' CBOR data encoded as a bytestring.
    
    :param subval: The value to be encoded and tagged.
    '''

    def __init__(self, subval):
        self.subval = subval


def default_encoder(encoder, value):
    if isinstance(value, BinaryEncodedCbor):
        # Tag 24: Encoded CBOR data item
        encoder.encode(cbor2.CBORTag(24, cbor2.dumps(value.subval)))


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
        pre_crc = cbor2.dumps(self.fields, default=default_encoder)
        crc_int = defn['func'](pre_crc)
        crc_value = defn['encode'](crc_int)
        self.fields[self.crc_field_ix] = crc_value

        post_crc = cbor2.dumps(self.fields, default=default_encoder)
        print('CRC',
              len(pre_crc), 
              b2a_hex(pre_crc), 
              b2a_hex(defn['encode'](defn['func'](pre_crc))),
              b2a_hex(defn['encode'](defn['xor'] ^ defn['func'](pre_crc))), 
              b2a_hex(crc_value), 
              b2a_hex(post_crc), 
              b2a_hex(defn['encode'](defn['func'](post_crc))))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    parser.add_argument('outfile', type=str)
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper())
    logging.debug('command args: %s', args)

    blocks = [
        Block(
            [  # primary block
                7,  # BP version
                0,  # bundle flags
                1,  # CRC type
                u'destination',
                u'source',
                u'report',
                [int(1e7), 0],  # creation timestamp
                int(1e5),  # lifetime
                FixedUInt16(0x0000),  # CRC
            ],
            crc_type_ix=2,
            crc_field_ix=8,
        ),
        Block(
            [  # extenstion
                100,  # block type
                3,  # block number
                0,  # block flags
                1,  # CRC type
                b'extdata',  # block data
                FixedUInt16(0x0000),  # CRC
            ],
            crc_type_ix=3,
            crc_field_ix=5,
        ),
        Block(
            [  # payload block
                1,  # block type
                0,  # block number
                0,  # block flags
                1,  # CRC type
                b'hithere',  # block data
                FixedUInt16(0x0000),  # CRC
            ],
            crc_type_ix=3,
            crc_field_ix=5,
        ),
        Block(
            [  # hop count
                9,  # block type
                0,  # block number
                0,  # block flags
                0,  # CRC type
                BinaryEncodedCbor([14, 8]),  # block data
            ]
        ),
    ]

    with open(args.outfile, 'wb') as outfile:
        outfile.write(b'\x9F')
        for block in blocks:
            block.update_crc()
            cbor2.dump(block.fields, outfile, default=default_encoder)
        outfile.write(b'\xFF')

    with open(args.outfile, 'rb') as outfile:
        print('Content:')
        print(cbor2.load(outfile))


if __name__ == '__main__':
    sys.exit(main())
