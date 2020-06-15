''' Test the module :py:mod:`bp.blocks`.
'''
import unittest
import cbor2
from bp.blocks import (CanonicalBlock, PrimaryBlock)


class TestPrimaryBlock(unittest.TestCase):

    def testSerializeDefault(self):
        block = PrimaryBlock()
        block.pre_encode()
        self.assertEqual(
            block.encode_cbor(),
            [
                7,
                0,
                0,
                '',
                '',
                '',
                [0, 0],
                0,
            ]
        )

    def testSerializeNofragment(self):
        block = PrimaryBlock(
            crc_type=2,
            destination='dtn://dst/',
            source='dtn://src/',
            report_to='dtn://rpt/',
            creation_timestamp=[1000, 3],
            lifetime=300,
        )
        block.pre_encode()
        self.assertEqual(
            block.encode_cbor(),
            [
                7,
                0,
                2,
                'dtn://dst/',
                'dtn://src/',
                'dtn://rpt/',
                [1000, 3],
                300,
                b'',
            ]
        )

    def testSerializeFragment(self):
        block = PrimaryBlock(
            bundle_flags=PrimaryBlock.Flag.BUNDLE_IS_FRAGMENT,
            crc_type=2,
            destination='dtn://dst/',
            source='dtn://src/',
            report_to='dtn://rpt/',
            creation_timestamp=[1000, 3],
            lifetime=300,
            fragment_offset=1000,
            total_app_data_len=2000,
        )
        block.pre_encode()
        self.assertEqual(
            block.encode_cbor(),
            [
                7,
                1,
                2,
                'dtn://dst/',
                'dtn://src/',
                'dtn://rpt/',
                [1000, 3],
                300,
                1000,
                2000,
                b''
            ]
        )


class TestCanonicalBlock(unittest.TestCase):

    def testSerializeDefault(self):
        block = CanonicalBlock()
        block.pre_encode()
        self.assertEqual(
            block.encode_cbor(),
            [
                cbor2.undefined,
                cbor2.undefined,
                0,
                0,
            ]
        )

    def testSerializeNopayload(self):
        block = CanonicalBlock(
            type_code=3,
            block_id=8,
        )
        block.pre_encode()
        self.assertEqual(
            block.encode_cbor(),
            [
                3,
                8,
                0,
                0,
            ]
        )
