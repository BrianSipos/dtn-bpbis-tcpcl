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

class SessionExtendHeader(packet.Packet):
    ''' Session Extension Item header. '''
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          # names in LSbit-first order
                          names=['CRITICAL']),
        formats.UInt16Field('type', default=None),
        formats.UInt32PayloadLenField('length', default=None),
    ]

class SessionInit(formats.NoPayloadPacket):
    ''' An SESS_INIT with no payload. '''
    
    #: Largest 64-bit size value
    SIZE_MAX = 2**64 - 1
    
    fields_desc = [
        formats.UInt16Field('keepalive', default=0),
        formats.UInt64Field('segment_mru', default=SIZE_MAX),
        formats.UInt64Field('transfer_mru', default=SIZE_MAX),
        
        formats.UInt16FieldLenField('eid_length', default=None,
                                    length_of='eid_data'),
        fields.StrLenField('eid_data', default='',
                           length_from=lambda pkt: pkt.eid_length),
        
        formats.UInt64FieldLenField('ext_size', default=None,
                                    length_of='ext_items'),
        fields.PacketListField('ext_items', default=[],
                               cls=SessionExtendHeader,
                               length_from=lambda pkt: pkt.ext_size),
    ]

class SessionTerm(formats.NoPayloadPacket):
    ''' An flag-dependent SESS_TERM message. '''
    #: MessageHead.flags mask
    FLAG_REASON = 0x2
    
    #: Disconnected because of idleness
    REASON_IDLE = 0
    #: ByteEnumField form
    REASONS = {
        REASON_IDLE: 'IDLE',
        1: 'VERSION_MISMATCH',
        2: 'BUSY',
        3: 'CONTACT_FAILURE',
        4: 'RESOURCE_EXHAUSTION',
    }
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          # names in LSbit-first order
                          names=[None, 'R']),
        fields.ConditionalField(fields.ByteEnumField('reason', default=None, enum=REASONS),
                                cond=lambda pkt: pkt.flags & SessionTerm.FLAG_REASON),
        
    ]

class Keepalive(formats.NoPayloadPacket):
    ''' An empty KEEPALIVE message. '''

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

#: Same encoding, different type IDs
TransferExtendHeader = SessionExtendHeader

class TransferInit(formats.NoPayloadPacket):
    ''' An XFER_INIT with no payload. '''
    
    fields_desc = [
        formats.UInt64Field('transfer_id', default=None),
        formats.UInt64Field('length', default=None),
        
        formats.UInt64FieldLenField('ext_size', default=None,
                                    length_of='ext_items'),
        fields.PacketListField('ext_items', default=[],
                               cls=TransferExtendHeader,
                               length_from=lambda pkt: pkt.ext_size),
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
packet.bind_layers(MessageHead, SessionTerm, msg_id=0x5)
packet.bind_layers(MessageHead, TransferInit, msg_id=0x6)
packet.bind_layers(MessageHead, RejectMsg, msg_id=0x7)
packet.bind_layers(MessageHead, SessionInit, msg_id=0x8)
