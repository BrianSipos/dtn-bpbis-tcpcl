
import struct
import datetime
import unittest
from scapy.packet import Packet
from .. import formats

class TestUInt16Field(unittest.TestCase):
    ''' Verify UInt16Field class '''
    
    class DummyPacket(Packet):
        fields_desc = [
            formats.UInt16Field('attr', None),
        ]
    
    def testSerialize(self):
        pkt = self.DummyPacket()
        fld = pkt.get_field('attr')
        self.assertIsNone(fld.default)
        
        # Default value
        self.assertIsNone(pkt.getfieldval('attr'))
        self.assertIsNone(pkt.attr)
        data = str(pkt)
        self.assertSequenceEqual(data, '0000'.decode('hex'))
        
        # Particular value
        testval = 0x30
        pkt.setfieldval('attr', testval)
        self.assertEqual(pkt.getfieldval('attr'), testval)
        self.assertEqual(pkt.attr, testval)
        data = str(pkt)
        self.assertSequenceEqual(data, '0030'.decode('hex'))
    
    def testDeserialize(self):
        testval = 0x40
        data = '\0\x40'
        pkt = self.DummyPacket(data)
        self.assertEqual(len(pkt), 2)
        self.assertEqual(pkt.getfieldval('attr'), testval)

class TestSdnvField(unittest.TestCase):
    ''' Verify SdnvField class '''
    
    class DummyPacket(Packet):
        explicit = 1
        fields_desc = [
            formats.SdnvField('attr', default=None),
        ]
    
    def testSerialize(self):
        pkt = self.DummyPacket()
        fld = pkt.get_field('attr')
        self.assertIsNone(fld.default)
        
        # Default value
        self.assertIsNone(pkt.getfieldval('attr'))
        self.assertIsNone(pkt.attr)
        data = str(pkt)
        self.assertSequenceEqual(data, '\0')
        
        # Particular value
        testval = 12345
        pkt.setfieldval('attr', testval)
        self.assertEqual(pkt.getfieldval('attr'), testval)
        self.assertEqual(pkt.attr, testval)
        data = str(pkt)
        self.assertSequenceEqual(data, 'e039'.decode('hex'))
    
    def testDeserialize(self):
        testval = 12345
        data = 'e039'.decode('hex')
        pkt = self.DummyPacket(data)
        self.assertEqual(len(pkt), 2)
        self.assertEqual(pkt.getfieldval('attr'), testval)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
