
from scapy import fields, packet
from . import formats

class NoPayloadPacket(packet.Packet):
    ''' A packet which never contains payload data.
    '''
    def extract_padding(self, s):
        ''' No payload, all extra data is padding '''
        return (None, s)

class Contact(NoPayloadPacket):
    ''' Contact header pseudo-message. '''
    #: Contact header magic head-data
    MAGIC_HEAD = 'dtn!'
    
    FLAG_ENA_ACK    = 0x01
    FLAG_ENA_FRAG   = 0x02
    FLAG_ENA_REFUSE = 0x04
    FLAG_ENA_LENGTH = 0x08
    
    fields_desc = [
        fields.StrFixedLenField('magic', default=MAGIC_HEAD, length=4),
        formats.UInt8Field('version', default=4),
        fields.FlagsField('flags', default=0, size=8,
                          # names in LSbit-first order
                          names=['ENA_ACK', 'ENA_FRAG', 'ENA_REFUSE', 'ENA_LENGTH']),
        formats.UInt16Field('keepalive', default=0),
        
        formats.SdnvFieldLenField('eid_length', default=None, length_of='eid_data'),
        fields.StrLenField('eid_data', default='',
                           length_from=lambda pkt: pkt.eid_length),
        
        formats.SdnvFieldLenField('bp_vers_count', default=None, count_of='bp_vers_list'),
        fields.FieldListField('bp_vers_list', default=[4],
                              field=formats.UInt8Field(None, default=None),
                              count_from=lambda pkt: pkt.bp_vers_count),
    ]

class MessageHead(packet.Packet):
    ''' The common message header. '''
    fields_desc = [
        fields.BitField('msg_id', default=None, size=4),
        fields.BitField('flags', default=0, size=4),
    ]

class Keepalive(NoPayloadPacket):
    ''' An empty KEEPALIVE message. '''

class StartTls(NoPayloadPacket):
    ''' An empty STARTTLS message. '''

class Shutdown(NoPayloadPacket):
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

class RejectMsg(NoPayloadPacket):
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

class BundleLength(NoPayloadPacket):
    ''' A LENGTH with no payload. '''
    
    fields_desc = [
        formats.SdnvField('bundle_id', default=None),
        formats.SdnvField('length', default=None),
    ]

class RefuseBundle(NoPayloadPacket):
    ''' An REFUSE_BUNDLE with no payload. '''
    
    REASON_UNKNOWN    = 0x0
    REASON_COMPLETED  = 0x1
    REASON_RESOURCES  = 0x2
    REASON_RETRANSMIT = 0x3
    
    fields_desc = [
        formats.SdnvField('bundle_id', default=None),
    ]

class DataSegment(NoPayloadPacket):
    ''' A DATA_SEGMENT with bundle data as payload. '''
    
    FLAG_START = 0x2
    FLAG_END   = 0x1
    
    fields_desc = [
        formats.SdnvField('bundle_id', default=None),
        formats.SdnvFieldLenField('length', default=None, length_of='data'),
        fields.StrFixedLenField('data', '', length_from=lambda pkt: pkt.length),
    ]

class AckSegment(NoPayloadPacket):
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
