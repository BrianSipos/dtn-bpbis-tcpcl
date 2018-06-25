
import unittest
from .. import messages

class TestSessionInit(unittest.TestCase):
    
    def testSerialize(self):
        pkt = messages.MessageHead()/messages.SessionInit()
        self.assertEqual(str(pkt).encode('hex'),
                         '08' + '0000' + 'ffffffffffffffff' + 'ffffffffffffffff' + '0000' + '0000000000000000')
        
        pkt = messages.MessageHead()/messages.SessionInit(
            keepalive=300,
            eid_data=u'hello'.encode('utf8'),
            segment_mru=1024,
            transfer_mru=10240,
        )
        self.assertSequenceEqual(
            str(pkt).encode('hex'), 
            '08' + '012c' + '0000000000000400' + '0000000000002800' + '0005' + 'hello'.encode('hex') + '0000000000000000'
        )
        
        pkt = messages.MessageHead()/messages.SessionInit(
            keepalive=300,
            eid_data=u'hello'.encode('utf8'),
            segment_mru=1024,
            transfer_mru=10240,
            ext_items=[
                messages.SessionExtendHeader(flags='CRITICAL')
            ],
        )
        self.assertSequenceEqual(
            str(pkt).encode('hex'), 
            '08' + '012c' + '0000000000000400' + '0000000000002800' + '0005' + 'hello'.encode('hex') + '0000000000000007' + '01' + '0000' + '00000000'
        )
    
    def testDeserialize(self):
        pkt = messages.MessageHead(('08' + '012c' + '0000000000000400' + '0000000000002800' + '0005' + 'hello'.encode('hex')).decode('hex'))
        self.assertEqual(pkt.msg_id, 8)
        self.assertIsInstance(pkt.payload, messages.SessionInit)
        self.assertEqual(pkt.payload.keepalive, 300)
        self.assertEqual(pkt.payload.segment_mru, 1024)
        self.assertEqual(pkt.payload.transfer_mru, 10240)
        self.assertEqual(pkt.payload.eid_data, 'hello')

class TestSessionTerm(unittest.TestCase):
    
    def testSerialize(self):
        pkt = messages.MessageHead()/messages.SessionTerm()
        self.assertSequenceEqual(str(pkt).encode('hex'), '0500')
        pkt = messages.MessageHead()/messages.SessionTerm(flags='R', reason=3)
        self.assertSequenceEqual(str(pkt).encode('hex'), '050203')

class TestKeepalive(unittest.TestCase):
    
    def testSerialize(self):
        pkt = messages.MessageHead()/messages.Keepalive()
        self.assertSequenceEqual(str(pkt).encode('hex'), '04')

class TestRejectMsg(unittest.TestCase):
    
    def testSerialize(self):
        pkt = messages.MessageHead()/messages.RejectMsg(rej_msg_id=7, reason='UNSUPPORTED')
        self.assertSequenceEqual(str(pkt).encode('hex'), '070702')

class TestTransferInit(unittest.TestCase):
    
    def testSerialize(self):
        pkt = messages.MessageHead()/messages.TransferInit(transfer_id=1234, length=543210)
        self.assertSequenceEqual(str(pkt).encode('hex'), '0600000000000004d200000000000849ea0000000000000000')

class TestTransferRefuse(unittest.TestCase):
    
    def testSerialize(self):
        pkt = messages.MessageHead()/messages.TransferRefuse(transfer_id=1234, reason='RESOURCES')
        self.assertSequenceEqual(str(pkt).encode('hex'), '030200000000000004d2')

class TestTransferSegment(unittest.TestCase):
    
    def testSerialize(self):
        pkt = messages.MessageHead()/messages.TransferSegment(transfer_id=1234, data='hello')
        self.assertSequenceEqual(str(pkt).encode('hex'), '010000000000000004d20000000000000005' + 'hello'.encode('hex'))

class TestTransferAck(unittest.TestCase):
    
    def testSerialize(self):
        pkt = messages.MessageHead()/messages.TransferAck(transfer_id=1234, length=43210)
        self.assertSequenceEqual(str(pkt).encode('hex'), '020000000000000004d2000000000000a8ca')
