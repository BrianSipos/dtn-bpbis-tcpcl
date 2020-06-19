''' Test the module :py:mod:`bp.blocks`.
'''
import binascii
import unittest
import cbor2
from scapy_cbor.fields import (UintField, TstrField)
from scapy_cbor.packets import (CborArray, CborItem)


class MockItem(CborItem):
    ''' A test structure. '''
    fields_desc = [
        TstrField('item', default=None),
    ]

class TestCborItem(unittest.TestCase):

    def testEncode(self):
        pkt = MockItem(item='hi')
        cbor_item = 'hi'

        self.assertEqual(
            pkt.self_build(),
            cbor_item
        )
        self.assertEqual(
            pkt.do_build(),
            cbor_item
        )
        self.assertEqual(
            pkt.build(),
            cbor_item
        )

        self.assertEqual(
            binascii.hexlify(bytes(pkt)),
            b'626869'
        )

    def testDecodeConstructor(self):
        cbor_item = 'hi'
        pkt = MockItem(cbor_item)
        self.assertEqual('hi', pkt.item)

    def testDecodeDissect(self):
        cbor_item = 'hi'
        pkt = MockItem()
        pkt.dissect(cbor_item)
        self.assertEqual('hi', pkt.item)

    def testDecodeBytes(self):
        cbor_bytes = binascii.unhexlify(b'626869')
        pkt = MockItem(cbor_bytes)
        self.assertEqual('hi', pkt.item)


class MockArray(CborArray):
    ''' A test structure. '''
    fields_desc = [
        UintField('fld_a', default=None),
        UintField('fld_b', default=None),
    ]


class TestCborArray(unittest.TestCase):

    def testEncode(self):
        pkt = MockArray(
            fld_a=3,
            fld_b=5,
        )

        cbor_item = [3, 5]
        self.assertEqual(
            pkt.self_build(),
            cbor_item
        )

        self.assertEqual(
            pkt.do_build(),
            cbor_item
        )

        self.assertEqual(
            pkt.build(),
            cbor_item
        )

        self.assertEqual(
            binascii.hexlify(bytes(pkt)),
            b'820305'
        )

    def testDecodeConstructor(self):
        cbor_item = [3, 5]
        pkt = MockArray(cbor_item)
        self.assertEqual(3, pkt.fld_a)
        self.assertEqual(5, pkt.fld_b)

    def testDecodeDissect(self):
        cbor_item = [3, 5]
        pkt = MockArray()
        pkt.dissect(cbor_item)
        self.assertEqual(3, pkt.fld_a)
        self.assertEqual(5, pkt.fld_b)

    def testDecodeBytes(self):
        cbor_bytes = binascii.unhexlify(b'820305')
        pkt = MockArray(cbor_bytes)
        self.assertEqual(3, pkt.fld_a)
        self.assertEqual(5, pkt.fld_b)
