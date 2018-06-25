
import unittest
from .. import contact

MAGIC_HEX = '64746e21'

class TestContact(unittest.TestCase):
    
    def testSerialize(self):
        pkt = contact.Head()/contact.ContactV4()
        self.assertEqual(str(pkt).encode('hex'),
                         MAGIC_HEX + '04' + '00')
        
        pkt = contact.Head()/contact.ContactV4(
            flags='CAN_TLS',
        )
        pkt.show()
        self.assertEqual(str(pkt).encode('hex'), 
                         MAGIC_HEX + '04' + '01')

    def testDeserialize(self):
        pkt = contact.Head((MAGIC_HEX + '04' + '00').decode('hex'))
        self.assertEqual(pkt.magic, 'dtn!')
        self.assertEqual(pkt.version, 4)
        self.assertFalse(pkt.flags & contact.ContactV4.FLAG_CAN_TLS)
        
        pkt = contact.Head((MAGIC_HEX + '04' + '01').decode('hex'))
        pkt.show()
        self.assertEqual(pkt.version, 4)
        self.assertTrue(pkt.flags & contact.ContactV4.FLAG_CAN_TLS)
