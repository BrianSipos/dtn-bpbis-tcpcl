
import unittest
from scapy.packet import Raw
from ..messages import *
from .. import xferextend

class TestSessionInit(unittest.TestCase):
    
    def testSerializeDefault(self):
        pkt = MessageHead()/SessionInit()
        self.assertEqual(
            str(pkt).encode('hex'),
            '08' + '0000' + 'ffffffffffffffff' + 'ffffffffffffffff' + '0000' + '00000000'
        )

    def testSerializeNoExt(self):
        pkt = MessageHead()/SessionInit(
            keepalive=300,
            eid_data=u'hello'.encode('utf8'),
            segment_mru=1024,
            transfer_mru=10240,
        )
        self.assertSequenceEqual(
            str(pkt).encode('hex'), 
            '08' + '012c' + '0000000000000400' + '0000000000002800' + '0005' + 'hello'.encode('hex')
            + '00000000'
        )

    def testDeserializeNoExt(self):
        pkt = MessageHead(('08' + '012c' + '0000000000000400' + '0000000000002800' + '0005' + 'hello'.encode('hex')).decode('hex'))
        self.assertEqual(pkt.msg_id, 8)
        self.assertIsInstance(pkt.payload, SessionInit)
        self.assertEqual(pkt.payload.keepalive, 300)
        self.assertEqual(pkt.payload.segment_mru, 1024)
        self.assertEqual(pkt.payload.transfer_mru, 10240)
        self.assertEqual(pkt.payload.eid_data, 'hello')

    def testSerializeEmptyExt(self):
        pkt = MessageHead()/SessionInit(
            keepalive=300,
            eid_data=u'hello'.encode('utf8'),
            segment_mru=1024,
            transfer_mru=10240,
            ext_items=[
                SessionExtendHeader(flags='CRITICAL', type=0xfffe)/Raw('exthi')
            ],
        )
        self.assertSequenceEqual(
            str(pkt).encode('hex'), 
            '08' + '012c' + '0000000000000400' + '0000000000002800' + '0005' + 'hello'.encode('hex')
            # extensions:
            + '0000000c'
            + '01' + 'fffe' + '00000005' + 'exthi'.encode('hex')
        )
    
class TestSessionTerm(unittest.TestCase):
    
    def testSerializeNoReason(self):
        pkt = MessageHead()/SessionTerm()
        self.assertSequenceEqual(str(pkt).encode('hex'), '050000')

    def testDeserializeNoReason(self):
        pkt = MessageHead(('05' + '0000').decode('hex'))
        self.assertEqual(pkt.msg_id, 5)
        self.assertIsInstance(pkt.payload, SessionTerm)
        self.assertEqual(pkt.payload.flags, 0)
        self.assertEqual(pkt.payload.reason, SessionTerm.REASON_UNKNOWN)

    def testSerializeWithReason(self):
        pkt = MessageHead()/SessionTerm(reason=3)
        self.assertSequenceEqual(str(pkt).encode('hex'), '050003')

    def testDeserializeWithReason(self):
        pkt = MessageHead(('05' + '0003').decode('hex'))
        self.assertEqual(pkt.msg_id, 5)
        self.assertIsInstance(pkt.payload, SessionTerm)
        self.assertEqual(pkt.payload.flags, 0)
        self.assertEqual(pkt.payload.reason, 3)

    def testSerializeAck(self):
        pkt = MessageHead()/SessionTerm(flags='ACK', reason=4)
        self.assertSequenceEqual(str(pkt).encode('hex'), '050104')

    def testDeserializeAck(self):
        pkt = MessageHead(('05' + '0104').decode('hex'))
        self.assertEqual(pkt.msg_id, 5)
        self.assertIsInstance(pkt.payload, SessionTerm)
        self.assertEqual(pkt.payload.flags, SessionTerm.FLAG_ACK)
        self.assertEqual(pkt.payload.reason, 4)

class TestKeepalive(unittest.TestCase):
    
    def testSerialize(self):
        pkt = MessageHead()/Keepalive()
        self.assertSequenceEqual(str(pkt).encode('hex'), '04')

    def testDeserialize(self):
        pkt = MessageHead(('0400').decode('hex'))
        self.assertEqual(pkt.msg_id, 4)
        self.assertIsInstance(pkt.payload, Keepalive)

class TestRejectMsg(unittest.TestCase):
    
    def testSerialize(self):
        pkt = MessageHead()/RejectMsg(rej_msg_id=7, reason=RejectMsg.REASON_UNSUPPORTED)
        self.assertSequenceEqual(str(pkt).encode('hex'), '070702')

    def testDeserialize(self):
        pkt = MessageHead(('070702').decode('hex'))
        self.assertEqual(pkt.msg_id, 7)
        self.assertIsInstance(pkt.payload, RejectMsg)
        self.assertEqual(pkt.payload.rej_msg_id, 7)
        self.assertEqual(pkt.payload.reason, RejectMsg.REASON_UNSUPPORTED)

class TestTransferRefuse(unittest.TestCase):
    
    def testSerialize(self):
        pkt = MessageHead()/TransferRefuse(transfer_id=1234, reason=TransferRefuse.REASON_RESOURCES)
        self.assertSequenceEqual(str(pkt).encode('hex'), '03' + '02' + '00000000000004d2')

    def testDeserialize(self):
        pkt = MessageHead(('03' + '02' + '00000000000004d2').decode('hex'))
        self.assertEqual(pkt.msg_id, 3)
        self.assertIsInstance(pkt.payload, TransferRefuse)
        self.assertEqual(pkt.payload.transfer_id, 1234)
        self.assertEqual(pkt.payload.reason, TransferRefuse.REASON_RESOURCES)

class TestTransferSegment(unittest.TestCase):

    def testSerializeStartNoExt(self):
        pkt = MessageHead()/TransferSegment(flags=TransferSegment.FLAG_START, transfer_id=1234, data='hello')
        self.assertSequenceEqual(
            str(pkt).encode('hex'),
            '01' + '02' + '00000000000004d2' 
            + '00000000' 
            + '0000000000000005' + 'hello'.encode('hex')
        )

    def testDeserializeStartNoExt(self):
        pkt = MessageHead((
            '01' + '02' + '00000000000004d2' 
            + '00000000' 
            + '0000000000000005' + 'hello'.encode('hex')
        ).decode('hex'))
        self.assertEqual(pkt.msg_id, 1)
        self.assertIsInstance(pkt.payload, TransferSegment)
        self.assertEqual(pkt.payload.flags, TransferSegment.FLAG_START)
        self.assertEqual(pkt.payload.transfer_id, 1234)
        self.assertEqual(pkt.payload.length, 5)
        self.assertEqual(pkt.payload.getfieldval('data'), 'hello')
        
        self.assertEqual(pkt.payload.ext_size, 0)
        self.assertEqual(len(pkt.payload.ext_items), 0)

    def testSerializeStartLengthExt(self):
        pkt = MessageHead()/TransferSegment(
            flags=TransferSegment.FLAG_START, 
            transfer_id=1234,
            ext_items=[
                TransferExtendHeader(flags='CRITICAL')/xferextend.Length(total_length=800)
            ],
            data='hello',
        )
        self.assertSequenceEqual(
            str(pkt).encode('hex'),
            '01' + '02' + '00000000000004d2' 
            # extensions:
            + '0000000f'
            + '01' + '0001' + '00000008' + '0000000000000320'
            # data
            + '0000000000000005' + 'hello'.encode('hex')
        )

    def testDeserializeStartLengthExt(self):
        pkt = MessageHead((
            '01' + '02' + '00000000000004d2' 
            + '0000000f'
            + '01' + '0001' + '00000008' + '0000000000000320'
            + '0000000000000005' + 'hello'.encode('hex')
        ).decode('hex'))
        self.assertEqual(pkt.msg_id, 1)
        self.assertIsInstance(pkt.payload, TransferSegment)
        self.assertEqual(pkt.payload.flags, TransferSegment.FLAG_START)
        self.assertEqual(pkt.payload.transfer_id, 1234)
        self.assertEqual(pkt.payload.length, 5)
        self.assertEqual(pkt.payload.getfieldval('data'), 'hello')

        self.assertEqual(pkt.payload.ext_size, 15)
        self.assertEqual(len(pkt.payload.ext_items), 1)
        # Items:
        item = pkt.payload.ext_items[0]
        self.assertEqual(item.flags, TransferExtendHeader.FLAG_CRITICAL)
        self.assertEqual(item.type, 1)
        self.assertEqual(item.length, 8)
        self.assertIsInstance(item.payload, xferextend.Length)
        self.assertEqual(item.payload.total_length, 800)

    def testSerializeMidData(self):
        pkt = MessageHead()/TransferSegment(transfer_id=1234, data='hello')
        self.assertSequenceEqual(str(pkt).encode('hex'), '01' + '00' + '00000000000004d2' + '0000000000000005' + 'hello'.encode('hex'))

    def testDeserializeMidData(self):
        pkt = MessageHead(('01' + '00' + '00000000000004d2' + '0000000000000005' + 'hello'.encode('hex')).decode('hex'))
        self.assertEqual(pkt.msg_id, 1)
        self.assertIsInstance(pkt.payload, TransferSegment)
        self.assertEqual(pkt.payload.flags, 0)
        self.assertEqual(pkt.payload.transfer_id, 1234)
        self.assertEqual(pkt.payload.length, 5)
        self.assertEqual(pkt.payload.getfieldval('data'), 'hello')

    def testSerializeEndData(self):
        pkt = MessageHead()/TransferSegment(flags=TransferSegment.FLAG_END, transfer_id=1234, data='hello')
        self.assertSequenceEqual(str(pkt).encode('hex'), '01' + '01' + '00000000000004d2' + '0000000000000005' + 'hello'.encode('hex'))

    def testDeserializeEndData(self):
        pkt = MessageHead((
            '01' + '01' + '00000000000004d2' 
            + '0000000000000005' + 'hello'.encode('hex')
        ).decode('hex'))
        self.assertEqual(pkt.msg_id, 1)
        self.assertIsInstance(pkt.payload, TransferSegment)
        self.assertEqual(pkt.payload.flags, TransferSegment.FLAG_END)
        self.assertEqual(pkt.payload.transfer_id, 1234)
        self.assertEqual(pkt.payload.length, 5)
        self.assertEqual(pkt.payload.getfieldval('data'), 'hello')

class TestTransferAck(unittest.TestCase):
    
    def testSerialize(self):
        pkt = MessageHead()/TransferAck(transfer_id=1234, flags=TransferSegment.FLAG_END, length=43210)
        self.assertSequenceEqual(
            str(pkt).encode('hex'),
            '02' + '01' + '00000000000004d2' + '000000000000a8ca'
        )

    def testDeserialize(self):
        pkt = MessageHead((
            '02' + '01' + '00000000000004d2' + '000000000000a8ca'
        ).decode('hex'))
        self.assertEqual(pkt.msg_id, 2)
        self.assertIsInstance(pkt.payload, TransferAck)
        self.assertEqual(pkt.payload.flags, TransferSegment.FLAG_END)
        self.assertEqual(pkt.payload.transfer_id, 1234)
        self.assertEqual(pkt.payload.length, 43210)
