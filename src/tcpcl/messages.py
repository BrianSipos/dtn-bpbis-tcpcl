''' Items related to established connection messaging.
'''

from scapy import fields, packet
from . import formats

class MessageHead(packet.Packet):
    ''' The common message header. '''
    fields_desc = [
        fields.BitField('msg_id', default=None, size=4),
        fields.BitField('flags', default=0, size=4),
    ]
    
    def post_dissection(self, pkt):
        ''' remove padding from payload list after disect() completes '''
        formats.remove_padding(self)
    
class Keepalive(formats.NoPayloadPacket):
    ''' An empty KEEPALIVE message. '''

class StartTls(formats.NoPayloadPacket):
    ''' An empty STARTTLS message. '''

class Shutdown(formats.NoPayloadPacket):
    ''' An flag-dependent SHUTDOWN message. '''
    #: MessageHead.flags mask
    FLAG_REASON = 0x2
    #: MessageHead.flags mask
    FLAG_DELAY = 0x1
    
    REASON_IDLE = 0
    REASON_TLS_FAIL = 4
    
    REASONS = {
        0: 'IDLE',
        1: 'CL_MISMATCH',
        2: 'BUSY',
        3: 'BP_MISMATCH',
        4: 'TLS_FAIL',
    }
    
    fields_desc = [
        fields.ConditionalField(fields.ByteEnumField('reason', default=None, enum=REASONS),
                                cond=lambda pkt: pkt.underlayer.flags & Shutdown.FLAG_REASON),
        fields.ConditionalField(formats.UInt16Field('conn_delay', default=None),
                                cond=lambda pkt: pkt.underlayer.flags & Shutdown.FLAG_DELAY)
        
    ]

class RejectMsg(formats.NoPayloadPacket):
    ''' A REJECT with no payload. '''
    
    REASON_UNKNOWN = 1
    REASON_UNSUPPORTED = 2
    REASON_UNEXPECTED = 3
    
    REASONS = {
        1: 'UNKNOWN',
        2: 'UNSUPPORTED',
        3: 'UNEXPECTED',
    }
    
    fields_desc = [
        fields.BitField('rej_id', default=None, size=4),
        fields.BitField('rej_flags', default=None, size=4),
        fields.ByteEnumField('reason', default=None, enum=REASONS),
    ]

class BundleLength(formats.NoPayloadPacket):
    ''' A LENGTH with no payload. '''
    
    fields_desc = [
        formats.SdnvField('bundle_id', default=None),
        formats.SdnvField('length', default=None),
    ]

class RefuseBundle(formats.NoPayloadPacket):
    ''' An REFUSE_BUNDLE with no payload. '''
    
    REASON_UNKNOWN    = 0x0
    REASON_COMPLETED  = 0x1
    REASON_RESOURCES  = 0x2
    REASON_RETRANSMIT = 0x3
    
    fields_desc = [
        formats.SdnvField('bundle_id', default=None),
    ]

class DataSegment(formats.NoPayloadPacket):
    ''' A DATA_SEGMENT with bundle data as payload. '''
    
    FLAG_START = 0x2
    FLAG_END   = 0x1
    
    fields_desc = [
        formats.SdnvField('bundle_id', default=None),
        formats.SdnvFieldLenField('length', default=None, length_of='data'),
        formats.BlobField('data', '', length_from=lambda pkt: pkt.length),
    ]

class AckSegment(formats.NoPayloadPacket):
    ''' An ACK_SEGMENT with no payload. '''
    
    fields_desc = [
        formats.SdnvField('bundle_id', default=None),
        formats.SdnvField('length', default=None),
    ]

packet.bind_layers(MessageHead, DataSegment, msg_id=0x1)
packet.bind_layers(MessageHead, AckSegment, msg_id=0x2)
packet.bind_layers(MessageHead, RefuseBundle, msg_id=0x3)
packet.bind_layers(MessageHead, Keepalive, msg_id=0x4)
packet.bind_layers(MessageHead, Shutdown, msg_id=0x5)
packet.bind_layers(MessageHead, BundleLength, msg_id=0x6)
packet.bind_layers(MessageHead, RejectMsg, msg_id=0x7)
packet.bind_layers(MessageHead, StartTls, msg_id=0x8)
