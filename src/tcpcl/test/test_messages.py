
import unittest
from scapy import packet
from .. import messages

class TestMessageLayering(unittest.TestCase):
    ''' Verify MessageHead class and message types '''
    
    def testSerialize(self):
        pkt = messages.MessageHead()/messages.Keepalive()
        self.assertSequenceEqual(str(pkt).encode('hex'), '04')
        
        pkt = messages.MessageHead()/messages.RejectMsg(rej_msg_id=7, reason='UNSUPPORTED')
        self.assertSequenceEqual(str(pkt).encode('hex'), '070702')
        
        pkt = messages.MessageHead()/messages.TransferInit(transfer_id=1234, length=543210)
        self.assertSequenceEqual(str(pkt).encode('hex'), '0600000000000004d200000000000849ea')
        
        pkt = messages.MessageHead()/messages.TransferRefuse(transfer_id=1234, reason='RESOURCES')
        self.assertSequenceEqual(str(pkt).encode('hex'), '030200000000000004d2')
        
        pkt = messages.MessageHead()/messages.TransferSegment(transfer_id=1234, data='hello')
        self.assertSequenceEqual(str(pkt).encode('hex'), '010000000000000004d20000000000000005' + 'hello'.encode('hex'))
        
        pkt = messages.MessageHead()/messages.TransferAck(transfer_id=1234, length=43210)
        self.assertSequenceEqual(str(pkt).encode('hex'), '020000000000000004d2000000000000a8ca')
        
        pkt = messages.MessageHead()/messages.Shutdown()
        self.assertSequenceEqual(str(pkt).encode('hex'), '0500')
        pkt = messages.MessageHead()/messages.Shutdown(flags='R', reason=3)
        self.assertSequenceEqual(str(pkt).encode('hex'), '050203')
        pkt = messages.MessageHead()/messages.Shutdown(flags='D', conn_delay=500)
        self.assertSequenceEqual(str(pkt).encode('hex'), '050101f4')
    
    def testDeserialize(self):
        pkt = messages.MessageHead('10895205' + 'hellothere'.encode('hex'))
        pkt.show()


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
