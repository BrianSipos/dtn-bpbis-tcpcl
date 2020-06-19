''' Test the module :py:mod:`bp.blocks`.
'''
import unittest
import cbor2
import scapy.packet
from scapy.config import conf
from bp.encoding import *

#: Encoded "dtn:none" URI
DTN_NONE = [int(EidField.TypeCode.dtn), 0]

conf.debug_dissector = True


class TestEidField(unittest.TestCase):

    def testEncode(self):
        fld = EidField('field')

        item = [
            EidField.TypeCode.dtn,
            '//node/serv',
        ]
        self.assertEqual(
            fld.i2m(None, 'dtn://node/serv'),
            item
        )

    def testDecode(self):
        fld = EidField('field')

        item = [
            EidField.TypeCode.dtn,
            '//node/serv',
        ]
        self.assertEqual(
            fld.m2i(None, item),
            'dtn://node/serv'
        )


class TestTimestampField(unittest.TestCase):

    def testEncode(self):
        fld = TimestampField('field')

        item = [
            1000,
            5
        ]
        self.assertEqual(
            fld.i2m(None, item),
            item
        )

        lst = []
        lst = fld.addfield(None, lst, item)
        self.assertEqual(
            lst,
            [item]
        )

    def testDecode(self):
        fld = TimestampField('field')

        item = [
            1000,
            5
        ]
        self.assertEqual(
            fld.m2i(None, item),
            item
        )

        lst = [item]
        (lst, val) = fld.getfield(None, lst)
        self.assertEqual(lst, [])
        self.assertEqual(val, item)


class BaseTestPacket(unittest.TestCase):
    ''' Include helper functions for scapy packet handling.
    '''

    def _encode(self, pkt):
        pkt.show()
        return pkt.build()

    def _decode(self, cls, item):
        pkt = cls(item)
        pkt.show()
        return pkt


class TestPrimaryBlock(BaseTestPacket):

    def testEncodeDefault(self):
        blk = PrimaryBlock()
        self.assertEqual(
            self._encode(blk),
            [
                7,
                0,
                0,
                DTN_NONE,
                DTN_NONE,
                DTN_NONE,
                [0, 0],
                0,
            ]
        )

    def testEncodeNofragment(self):
        blk = PrimaryBlock(
            crc_type=2,
            destination='dtn://dst/',
            source='dtn://src/',
            report_to='dtn://rpt/',
            creation_timestamp=[1000, 3],
            lifetime=300,
        )
        self.assertEqual(
            self._encode(blk),
            [
                7,
                0,
                2,
                [EidField.TypeCode.dtn, '//dst/'],
                [EidField.TypeCode.dtn, '//src/'],
                [EidField.TypeCode.dtn, '//rpt/'],
                [1000, 3],
                300,
                None,
            ]
        )

    def testDecodeNofragment(self):
        item = [
            7,
            0,
            2,
            [EidField.TypeCode.dtn, '//dst/'],
            [EidField.TypeCode.dtn, '//src/'],
            [EidField.TypeCode.dtn, '//rpt/'],
            [1000, 3],
            300,
            None,
        ]
        blk = self._decode(PrimaryBlock, item)
        self.assertEqual(2, blk.crc_type)
        self.assertEqual('dtn://dst/', blk.destination)
        self.assertEqual('dtn://src/', blk.source)
        self.assertEqual('dtn://rpt/', blk.report_to)
        self.assertEqual(['2000-01-01T00:16:40+00:00', 3], blk.creation_timestamp)
        self.assertEqual(300, blk.lifetime)

    def testEncodeFragment(self):
        blk = PrimaryBlock(
            bundle_flags=PrimaryBlock.Flag.BUNDLE_IS_FRAGMENT,
            crc_type=2,
            destination='dtn://dst/',
            source='dtn://src/',
            report_to='dtn://rpt/',
            creation_timestamp=['2000-01-01T00:16:40+00:00', 3],
            lifetime=300,
            fragment_offset=1000,
            total_app_data_len=2000,
        )
        self.assertEqual(
            self._encode(blk),
            [
                7,
                1,
                2,
                [EidField.TypeCode.dtn, '//dst/'],
                [EidField.TypeCode.dtn, '//src/'],
                [EidField.TypeCode.dtn, '//rpt/'],
                [1000, 3],
                300,
                1000,
                2000,
                None
            ]
        )

    def testDecodeFragment(self):
        item = [
            7,
            1,
            2,
            [EidField.TypeCode.dtn, '//dst/'],
            [EidField.TypeCode.dtn, '//src/'],
            [EidField.TypeCode.dtn, '//rpt/'],
            [1000, 3],
            300,
            1000,
            2000,
            None
        ]
        blk = self._decode(PrimaryBlock, item)
        self.assertEqual(2, blk.crc_type)
        self.assertEqual('dtn://dst/', blk.destination)
        self.assertEqual('dtn://src/', blk.source)
        self.assertEqual('dtn://rpt/', blk.report_to)
        self.assertEqual(['2000-01-01T00:16:40+00:00', 3], blk.creation_timestamp)
        self.assertEqual(300, blk.lifetime)


class TestCanonicalBlock(BaseTestPacket):

    def testEncodeDefault(self):
        blk = CanonicalBlock()
        self.assertEqual(
            self._encode(blk),
            [
                None,
                None,
                0,
                0,
                None,
            ]
        )

    def testEncodeNoData(self):
        blk = CanonicalBlock(
            type_code=3,
            block_num=8,
        )
        self.assertEqual(
            self._encode(blk),
            [
                3,
                8,
                0,
                0,
                None,
            ]
        )

    def testEncodeRawData(self):
        blk = CanonicalBlock(
            type_code=1,
            block_num=8,
            data=b'hi'
        )
        self.assertEqual(
            self._encode(blk),
            [
                1,
                8,
                0,
                0,
                b'hi'
            ]
        )


class TestBundle(BaseTestPacket):

    def testEncodeEmpty(self):
        bdl = Bundle()
        self.assertEqual(
            self._encode(bdl),
            [
                None,  # missing primary
            ]
        )

    def testEncodeOnlyPrimary(self):
        bdl = Bundle(
            primary=PrimaryBlock(),
        )
        self.assertEqual(
            self._encode(bdl),
            [
                [
                    7,
                    0,
                    0,
                    DTN_NONE,
                    DTN_NONE,
                    DTN_NONE,
                    [0, 0],
                    0,
                ],
            ]
        )

    def testDecodeOnlyPrimary(self):
        item = [
            [
                7,
                0,
                0,
                DTN_NONE,
                DTN_NONE,
                DTN_NONE,
                [0, 0],
                0,
            ],
        ]
        bdl = self._decode(Bundle, item)

        self.assertIsNotNone(bdl.primary)
        blk = bdl.primary
        self.assertEqual(blk.bp_version, 7)
        self.assertEqual(blk.bundle_flags, 0)
        self.assertEqual(blk.crc_type, 0)

        self.assertEqual(len(bdl.blocks), 0)

    def testEncodePayload(self):
        pyld_data = cbor2.dumps(['some', 'data'])
        bdl = Bundle(
            primary=PrimaryBlock(),
            blocks=[
                CanonicalBlock(
                    block_num=1,
                    data=pyld_data,
                ),
            ]
        )
        self.assertEqual(
            self._encode(bdl),
            [
                [
                    7,
                    0,
                    0,
                    DTN_NONE,
                    DTN_NONE,
                    DTN_NONE,
                    [0, 0],
                    0,
                ],
                [
                    None,
                    1,
                    0,
                    0,
                    pyld_data,
                ],
            ]
        )

    def testDecodePayload(self):
        pyld_data = cbor2.dumps(['some', 'data'])
        item = [
            [
                7,
                0,
                0,
                DTN_NONE,
                DTN_NONE,
                DTN_NONE,
                [0, 0],
                0,
            ],
            [
                1,
                8,
                0,
                0,
                pyld_data,
            ],
        ]
        bdl = self._decode(Bundle, item)

        self.assertIsNotNone(bdl.primary)

        self.assertEqual(len(bdl.blocks), 1)
        blk = bdl.blocks[0]
        self.assertEqual(blk.type_code, 1)
        self.assertEqual(blk.block_num, 8)
        self.assertEqual(blk.data, pyld_data)


class TestBundleAgeBlockData(BaseTestPacket):

    def testEncode(self):
        blk = CanonicalBlock() / BundleAgeBlockData(age=10)

        self.assertEqual(
            self._encode(blk),
            [
                7,
                None,
                0,
                0,
                cbor2.dumps(10),
            ]
        )

    def testDecode(self):
        item = [
            7,
            None,
            0,
            0,
            cbor2.dumps(10),
        ]
        blk = self._decode(CanonicalBlock, item)
        self.assertEqual(blk.type_code, 7)
        self.assertEqual(blk.block_num, None)

        self.assertEqual(type(blk.payload), BundleAgeBlockData)
        self.assertEqual(blk.payload.age, 10)


class TestAdminRecord(BaseTestPacket):

    def testEncodeEmpy(self):
        pkt = AdminRecord()

        self.assertEqual(
            self._encode(pkt),
            [
                None,
                None
            ]
        )

    def testDecodeEmpty(self):
        item = [
            None,
            None,
        ]
        pkt = self._decode(AdminRecord, item)
        self.assertEqual(pkt.type_code, None)

        self.assertEqual(type(pkt.payload), scapy.packet.NoPayload)

class TestAdminRecord(BaseTestPacket):

    def testEncodeEmpy(self):
        pkt = AdminRecord()

        self.assertEqual(
            self._encode(pkt),
            [
                None,
                None
            ]
        )

    def testDecodeEmpty(self):
        item = [
            None,
            None,
        ]
        pkt = self._decode(AdminRecord, item)
        self.assertEqual(pkt.type_code, None)

        self.assertEqual(type(pkt.payload), scapy.packet.NoPayload)
 