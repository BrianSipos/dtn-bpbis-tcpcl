
import unittest
from scapy import packet
from .. import contact

MAGIC_HEX = '64746e21'

class TestContact(unittest.TestCase):
    
    def testSerialize(self):
        pkt = contact.Head()/contact.ContactV4()
        self.assertEqual(str(pkt).encode('hex'), MAGIC_HEX + '0400')
        
        pkt = contact.Head()/contact.ContactV4()
        pkt.options = [
            contact.OptionHead()/contact.OptionKeepalive(keepalive=300),
            contact.OptionHead()/contact.OptionEid(eid_data=u'hello'.encode('utf8')),
            contact.OptionHead()/contact.OptionBpVersion(bp_vers_list = [3,4]),
            contact.OptionHead()/contact.OptionMru(segment_size=1024, bundle_size=10240),
        ]
        pkt.show()
        self.assertEqual(str(pkt).encode('hex'), 
                         MAGIC_HEX + '0404' + '0602012c' + '070568656c6c6f' + '0803020304' + '09048800d000')
    
    def testDeserialize(self):
        pkt = contact.Head((MAGIC_HEX + '0400').decode('hex'))
        self.assertEqual(pkt.magic, 'dtn!')
        self.assertEqual(pkt.version, 4)
        self.assertEqual(pkt.options, [])
        
        pkt = contact.Head((MAGIC_HEX + '0404' + '0602012c' + '07026869' + '0803020304' + '09048800d000').decode('hex'))
        pkt.show()
        self.assertEqual(pkt.version, 4)
        self.assertEqual(pkt.option_count, 4)
        
        opt = pkt.payload.get_option(contact.OptionKeepalive)
        self.assertEqual(opt.keepalive, 300)
        opt = pkt.payload.get_option(contact.OptionEid)
        self.assertEqual(opt.eid_data, 'hi')
        opt = pkt.payload.get_option(contact.OptionBpVersion)
        self.assertEqual(opt.bp_vers_list, [3,4])
        opt = pkt.payload.get_option(contact.OptionMru)
        self.assertEqual(opt.segment_size, 1024)
        self.assertEqual(opt.bundle_size, 10240)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
