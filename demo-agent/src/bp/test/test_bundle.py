''' Test the module :py:mod:`bp.bundle`.
'''
import unittest
from bp.bundle import (Bundle)
from bp.blocks import (PrimaryBlock, CanonicalBlock, Payload)

class TestBundle(unittest.TestCase):

    def testSerializeEmpty(self):
        bdl = Bundle()
        with self.assertRaises(RuntimeError):
            bdl.encode_cbor()

    def testSerializeMinimal(self):
        bdl = Bundle(blocks=[
            PrimaryBlock(
            ),
            CanonicalBlock() / Payload(),
        ])
        self.assertEqual(
            bdl.encode_cbor(),
            [7, 0, 0, '', '', '', [0, 0], 0]
        )
