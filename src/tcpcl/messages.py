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
        
        if not self.payload:
            raise formats.VerifyError('Message without payload')
        if isinstance(self.payload, packet.Raw):
            raise formats.VerifyError('Message with improper payload')
        
        packet.Packet.post_dissection(self, pkt)

class TlvHead(packet.Packet):
    ''' Generic TLV header with data as payload. '''
    
    FLAG_CRITICAL = 0x01
    #: In FlagsField form (LSbit-first order)
    FLAGS_NAMES = ['CRITICAL']
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          names=FLAGS_NAMES),
        formats.UInt16Field('type', default=None),
        formats.UInt32PayloadLenField('length', default=None),
    ]
    
    def post_dissection(self, pkt):
        ''' Verify consistency of packet. '''
        formats.verify_sized_item(self.length, self.payload)
        packet.Packet.post_dissection(self, pkt)

class SessionExtendHeader(TlvHead):
    ''' Session Extension Item header with data as payload. '''

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
        
        formats.UInt32FieldLenField('ext_size', default=None,
                                    length_of='ext_items'),
        fields.PacketListField('ext_items', default=[],
                               cls=SessionExtendHeader,
                               length_from=lambda pkt: pkt.ext_size),
    ]
    
    def post_dissection(self, pkt):
        ''' Verify consistency of packet. '''
        formats.verify_sized_item(self.eid_length, self.eid_data)

        (field, val) = self.getfield_and_val('ext_items')
        if val is not None:
            encoded = field.addfield(self, '', val)
            formats.verify_sized_item(self.ext_size, encoded)

        packet.Packet.post_dissection(self, pkt)

class SessionTerm(formats.NoPayloadPacket):
    ''' An flag-dependent SESS_TERM message. '''
    
    FLAG_ACK = 0x01
    #: In FlagsField form (LSbit-first order)
    FLAGS_NAMES = ['ACK']
    
    REASON_UNKNOWN = 0
    #: ByteEnumField form
    REASONS = {
        REASON_UNKNOWN: 'UNKNOWN',
        1: 'IDLE_TIMEOUT',
        2: 'VERSION_MISMATCH',
        3: 'BUSY',
        4: 'CONTACT_FAILURE',
        5: 'RESOURCE_EXHAUSTION',
    }
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          names=FLAGS_NAMES),
        fields.ByteEnumField('reason', default=None, enum=REASONS),
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

class TransferExtendHeader(TlvHead):
    ''' Transfer Extension Item header with data as payload. '''

class TransferRefuse(formats.NoPayloadPacket):
    ''' An XFER_REFUSE with no payload. '''
    
    REASON_UNKNOWN    = 0x0
    REASON_COMPLETED  = 0x1
    REASON_RESOURCES  = 0x2
    REASON_RETRANSMIT = 0x3
    #: ByteEnumField form
    REASONS = {
        REASON_UNKNOWN: 'UNKNOWN',
        REASON_COMPLETED: 'COMPLETED',
        REASON_RESOURCES: 'RESOURCES',
        REASON_RETRANSMIT: 'RETRANSMIT',
    }
    
    fields_desc = [
        fields.ByteEnumField('reason', default=None, enum=REASONS),
        formats.UInt64Field('transfer_id', default=None),
    ]

class TransferSegment(formats.NoPayloadPacket):
    ''' A XFER_SEGMENT with bundle data as field. '''
    
    FLAG_START = 0x2
    FLAG_END   = 0x1
    #: In FlagsField form (LSbit-first order)
    FLAGS_NAMES = ['END', 'START']
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          names=FLAGS_NAMES),
        formats.UInt64Field('transfer_id', default=None),
        fields.ConditionalField(
            cond=lambda pkt: pkt.flags & TransferSegment.FLAG_START,
            fld=formats.UInt32FieldLenField('ext_size', default=None, length_of='ext_items'),
        ),
        fields.ConditionalField(
            cond=lambda pkt: pkt.flags & TransferSegment.FLAG_START,
            fld=fields.PacketListField('ext_items', default=[],
                                       cls=TransferExtendHeader,
                                       length_from=lambda pkt: pkt.ext_size),
        ),
        formats.UInt64FieldLenField('length', default=None, length_of='data'),
        formats.BlobField('data', '', length_from=lambda pkt: pkt.length),
    ]
    
    def post_dissection(self, pkt):
        ''' Verify consistency of packet. '''
        (field, val) = self.getfield_and_val('ext_items')
        if val is not None:
            encoded = field.addfield(self, '', val)
            formats.verify_sized_item(self.ext_size, encoded)
        
        formats.verify_sized_item(self.length, self.getfieldval('data'))
        packet.Packet.post_dissection(self, pkt)

class TransferAck(formats.NoPayloadPacket):
    ''' An XFER_ACK with no payload. '''
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          names=TransferSegment.FLAGS_NAMES),
        formats.UInt64Field('transfer_id', default=None),
        formats.UInt64Field('length', default=None),
    ]

packet.bind_layers(MessageHead, TransferSegment, msg_id=0x1)
packet.bind_layers(MessageHead, TransferAck, msg_id=0x2)
packet.bind_layers(MessageHead, TransferRefuse, msg_id=0x3)
packet.bind_layers(MessageHead, Keepalive, msg_id=0x4)
packet.bind_layers(MessageHead, SessionTerm, msg_id=0x5)
packet.bind_layers(MessageHead, RejectMsg, msg_id=0x7)
packet.bind_layers(MessageHead, SessionInit, msg_id=0x8)
