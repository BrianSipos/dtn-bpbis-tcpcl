''' Items related to contact header and connection negotiation.
'''

from scapy import fields, packet
from . import formats


#: Header magic prefix-data
MAGIC_HEAD = 'dtn!'

class Head(packet.Packet):
    ''' Front elements common to the TCPCL contact headers. '''
    fields_desc = [
        fields.StrFixedLenField('magic', default=MAGIC_HEAD, length=4),
        formats.UInt8Field('version', default=None),
    ]

class ContactV3(formats.NoPayloadPacket):
    ''' TCPCLv3 contact header pseudo-message. '''
    
    FLAG_ENA_ACK    = 0x01
    FLAG_ENA_FRAG   = 0x02
    FLAG_ENA_REFUSE = 0x04
    FLAG_ENA_LENGTH = 0x08
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          # names in LSbit-first order
                          names=['ENA_ACK', 'ENA_FRAG', 'ENA_REFUSE', 'ENA_LENGTH']),
        formats.UInt16Field('keepalive', default=0),
        
        formats.SdnvFieldLenField('eid_length', default=None, length_of='eid_data'),
        fields.StrLenField('eid_data', default='',
                           length_from=lambda pkt: pkt.eid_length),
    ]
packet.bind_layers(Head, ContactV3, version=3)

class ContactV4ExtendHeader(packet.Packet):
    ''' TCPCLv4 Extension item header. '''
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          # names in LSbit-first order
                          names=['CRITICAL']),
        formats.UInt16Field('type', default=None),
        formats.UInt32PayloadLenField('length', default=None),
    ]

class ExtendItemReactiveFragment(packet.Packet):
    ''' Extension type for reactive fragmentation negotiation. '''
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          # names in LSbit-first order
                          names=['CAN_GENERATE', 'CAN_RECEIVE']),
    ]
packet.bind_layers(ContactV4ExtendHeader, ExtendItemReactiveFragment, type=0x0001)

class ContactV4(formats.NoPayloadPacket):
    ''' TCPCLv4 Contact header pseudo-message. '''
    
    #: Largest 64-bit size value
    SIZE_MAX = 2**64 - 1
    #: Sender can use TLS
    FLAG_CAN_TLS = 0x01
    
    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          # names in LSbit-first order
                          names=['CAN_TLS']),
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
                               cls=ContactV4ExtendHeader,
                               length_from=lambda pkt: pkt.ext_size),
    ]
packet.bind_layers(Head, ContactV4, version=4)
