''' Items related to established connection messaging.
'''

from scapy import fields, packet
from . import formats

class MessageHead(packet.Packet):
    ''' The common message header. '''
    fields_desc = [
        formats.UInt8Field('msg_id', default=None),
    ]
    
    def post_dissection(self, pkt):
        ''' remove padding from payload list after disect() completes '''
        formats.remove_padding(self)
    
class Keepalive(formats.NoPayloadPacket):
    ''' An empty KEEPALIVE message. '''

class Shutdown(formats.NoPayloadPacket):
    ''' An flag-dependent SHUTDOWN message. '''
    #: MessageHead.flags mask
    FLAG_REASON = 0x2
    #: MessageHead.flags mask
    FLAG_DELAY = 0x1
    
    #: Disconnected because of idleness
    REASON_IDLE = 0
    #: Disconnected because TLS negotiation failed
    REASON_TLS_FAIL = 4
    #: ByteEnumField form
    REASONS = {
        REASON_IDLE: 'IDLE',
        1: 'CL_MISMATCH',
        2: 'BUSY',
        3: 'BP_MISMATCH',
        REASON_TLS_FAIL: 'TLS_FAIL',
    }
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          # names in LSbit-first order
                          names=['D', 'R']),
        fields.ConditionalField(fields.ByteEnumField('reason', default=None, enum=REASONS),
                                cond=lambda pkt: pkt.flags & Shutdown.FLAG_REASON),
        fields.ConditionalField(formats.UInt16Field('conn_delay', default=None),
                                cond=lambda pkt: pkt.flags & Shutdown.FLAG_DELAY)
        
    ]

class RejectMsg(formats.NoPayloadPacket):
    ''' A REJECT with no payload. '''
    
    REASON_UNKNOWN = 1
    REASON_UNSUPPORTED = 2
    REASON_UNEXPECTED = 3
    
    #: ByteEnumField form
    REASONS = {
        1: 'UNKNOWN',
        2: 'UNSUPPORTED',
        3: 'UNEXPECTED',
    }
    
    fields_desc = [
        formats.UInt8Field('rej_msg_id', default=None),
        fields.ByteEnumField('reason', default=None, enum=REASONS),
    ]

class TransferInit(formats.NoPayloadPacket):
    ''' A LENGTH with no payload. '''
    
    fields_desc = [
        formats.UInt64Field('transfer_id', default=None),
        formats.UInt64Field('length', default=None),
    ]

class TransferRefuse(formats.NoPayloadPacket):
    ''' An XFER_REFUSE with no payload. '''
    
    REASON_UNKNOWN    = 0x0
    REASON_COMPLETED  = 0x1
    REASON_RESOURCES  = 0x2
    REASON_RETRANSMIT = 0x3
    #: ByteEnumField form
    REASONS = {
        0: 'UNKNOWN',
        1: 'COMPLETED',
        2: 'RESOURCES',
        3: 'RETRANSMIT',
    }
    
    fields_desc = [
        fields.ByteEnumField('reason', default=None, enum=REASONS),
        formats.UInt64Field('transfer_id', default=None),
    ]

class TransferSegment(formats.NoPayloadPacket):
    ''' A XFER_SEGMENT with bundle data as payload. '''
    
    FLAG_START = 0x2
    FLAG_END   = 0x1
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          # names in LSbit-first order
                          names=['E', 'S']),
        formats.UInt64Field('transfer_id', default=None),
        formats.UInt64FieldLenField('length', default=None, length_of='data'),
        formats.BlobField('data', '', length_from=lambda pkt: pkt.length),
    ]

class TransferAck(formats.NoPayloadPacket):
    ''' An XFER_ACK with no payload. '''
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          # names in LSbit-first order
                          names=['E', 'S']),
        formats.UInt64Field('transfer_id', default=None),
        formats.UInt64Field('length', default=None),
    ]

packet.bind_layers(MessageHead, TransferSegment, msg_id=0x1)
packet.bind_layers(MessageHead, TransferAck, msg_id=0x2)
packet.bind_layers(MessageHead, TransferRefuse, msg_id=0x3)
packet.bind_layers(MessageHead, Keepalive, msg_id=0x4)
packet.bind_layers(MessageHead, Shutdown, msg_id=0x5)
packet.bind_layers(MessageHead, TransferInit, msg_id=0x6)
packet.bind_layers(MessageHead, RejectMsg, msg_id=0x7)
