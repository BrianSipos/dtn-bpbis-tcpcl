
import unittest
from scapy import packet
from .. import contact

MAGIC_HEX = '64746e21'

class TestContact(unittest.TestCase):
    
    def testSerialize(self):
        pkt = contact.Head()/contact.ContactV4()
        self.assertEqual(str(pkt).encode('hex'),
                         MAGIC_HEX + '04' + '00' + '0000' + 'ffffffffffffffff' + 'ffffffffffffffff' + '0000' + '0000000000000000')
        
        pkt = contact.Head()/contact.ContactV4(
            keepalive=300,
            eid_data=u'hello'.encode('utf8'),
            segment_mru=1024,
            transfer_mru=10240,
        )
        pkt.show()
        self.assertEqual(str(pkt).encode('hex'), 
                         MAGIC_HEX + '04' + '00' + '012c' + '0000000000000400' + '0000000000002800' + '0005' + 'hello'.encode('hex') + '0000000000000000')
        
        pkt = contact.Head()/contact.ContactV4(
            keepalive=300,
            eid_data=u'hello'.encode('utf8'),
            segment_mru=1024,
            transfer_mru=10240,
            ext_items=[
                contact.ContactV4ExtendHeader(flags='CRITICAL')/contact.DummyExtend(data='hithere')
            ],
        )
        pkt.show2()
        self.assertEqual(str(pkt).encode('hex'), 
                         MAGIC_HEX + '04' + '00' + '012c' + '0000000000000400' + '0000000000002800' + '0005' + 'hello'.encode('hex') + '000000000000000e' + '01' + '8000' + '00000007' + '68697468657265')
    
    def testDeserialize(self):
        pkt = contact.Head((MAGIC_HEX + '0400').decode('hex'))
        self.assertEqual(pkt.magic, 'dtn!')
        self.assertEqual(pkt.version, 4)
        self.assertEqual(pkt.payload.keepalive, 0)
        self.assertEqual(pkt.payload.segment_mru, 2**64-1)
        self.assertEqual(pkt.payload.transfer_mru, 2**64-1)
        self.assertEqual(pkt.payload.eid_data, '')
        
        pkt = contact.Head((MAGIC_HEX + '04' + '00' + '012c' + '0000000000000400' + '0000000000002800' + '0005' + 'hello'.encode('hex')).decode('hex'))
        pkt.show()
        self.assertEqual(pkt.version, 4)
        self.assertEqual(pkt.payload.keepalive, 300)
        self.assertEqual(pkt.payload.segment_mru, 1024)
        self.assertEqual(pkt.payload.transfer_mru, 10240)
        self.assertEqual(pkt.payload.eid_data, 'hello')


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
