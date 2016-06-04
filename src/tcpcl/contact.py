''' Items related to contact header and connection negotiation.
'''

from scapy import fields, packet
from . import formats

class OptionHead(packet.Packet):
    ''' Header for an abstract contact option.
    The payload of this packet is a specific contact option packet.
    '''
    fields_desc = [
        formats.SdnvField('type', default=None),
        formats.SdnvPayloadLenField('length', default=None),
    ]

class MessageRxField(fields.FlagsField):
    ''' Define how the receiver handles received messages.
    '''
    #: Receiver ignores these messages
    FLAG_IGNORE  = 0x01
    #: Receiver allows these messages
    FLAG_ALLOW   = 0x02
    #: Receiver requires these messsages
    FLAG_REQUIRE = 0x04
    #: flags in LSbit order
    NAMES = ['IGNORE', 'ALLOW', 'REQUIRE']
    
    def __init__(self, name, default):
        fields.FlagsField.__init__(self, name, default, size=8, names=self.NAMES)

class OptionLength(formats.NoPayloadPacket):
    ''' Receiver handling of LENGTH.
    '''
    fields_desc = [
        MessageRxField('accept', default=MessageRxField.FLAG_ALLOW),
    ]
packet.bind_layers(OptionHead, OptionLength, type=0x01)

class OptionAck(formats.NoPayloadPacket):
    ''' Receiver handling of ACK_SEGMENT.
    '''
    fields_desc = [
        MessageRxField('accept', default=MessageRxField.FLAG_ALLOW),
    ]
packet.bind_layers(OptionHead, OptionAck, type=0x02)

class OptionRefuse(formats.NoPayloadPacket):
    ''' Receiver handling of REFUSE_BUNDLE.
    '''
    fields_desc = [
        MessageRxField('accept', default=MessageRxField.FLAG_ALLOW),
    ]
packet.bind_layers(OptionHead, OptionRefuse, type=0x03)

class OptionKeepalive(formats.NoPayloadPacket):
    ''' The maximum keepalive interval.
    '''
    fields_desc = [
        formats.UInt16Field('keepalive', default=0),
    ]
packet.bind_layers(OptionHead, OptionKeepalive, type=0x06)

def len_or_under(pkt_attr, under_attr):
    ''' Define a function which returns either the length of a packet value
    or a packet under-layer value.
    
    :param pkt_attr: The packet field name to try first.
    :param under_attr: The underlayer field name to try second.
    :return: A length-returning function.
    '''
    def fun(pkt):
        pktval = pkt.getfieldval(pkt_attr)
        if pktval is not None:
            return len(pktval)
        else:
            return pkt.underlayer.getfieldval(under_attr)
    return fun

class OptionEid(formats.NoPayloadPacket):
    ''' The full EID of the sending endpoint.
    '''
        
    fields_desc = [
        fields.StrFixedLenField('eid_data', default=None,
                                length_from=len_or_under('eid_data', 'length')),
    ]
packet.bind_layers(OptionHead, OptionEid, type=0x07)

class OptionBpVersion(formats.NoPayloadPacket):
    ''' A list of BP version identifiers supported by the sender.
    '''
    fields_desc = [
        formats.SdnvFieldLenField('bp_vers_count', default=None, count_of='bp_vers_list'),
        fields.FieldListField('bp_vers_list', default=[4],
                              field=formats.UInt8Field(None, default=None),
                              count_from=lambda pkt: pkt.bp_vers_count),
    ]
packet.bind_layers(OptionHead, OptionBpVersion, type=0x08)

class OptionMru(formats.NoPayloadPacket):
    ''' The maximum receive size in octets.
    '''
        
    fields_desc = [
        formats.SdnvField('segment_size', default=None),
        formats.SdnvField('bundle_size', default=None),
    ]
packet.bind_layers(OptionHead, OptionMru, type=0x09)

class OptionTls(formats.NoPayloadPacket):
    ''' Whether the endpoint supports TLS connection.
    '''
        
    fields_desc = [
        MessageRxField('accept', default=MessageRxField.FLAG_ALLOW),
    ]
packet.bind_layers(OptionHead, OptionTls, type=0x0a)


#: Header magic prefix-data
MAGIC_HEAD = 'dtn!'

class Head(packet.Packet):
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

class ContactV4(formats.NoPayloadPacket):
    ''' TCPCLv4 Contact header pseudo-message. '''
    
    fields_desc = [
        formats.SdnvFieldLenField('option_count', default=None, count_of='options'),
        fields.PacketListField('options', default=[], cls=OptionHead,
                               count_from=lambda pkt: pkt.option_count)
    ]
    
    def find_option(self, cls):
        valid = []
        for opt in self.options:
            if isinstance(opt.payload, cls):
                valid.append(opt.payload)
        if len(valid) > 1:
            raise KeyError('more than one option present')
        if len(valid) < 1:
            return cls()
        return valid[0]
    
    def get_option(self, cls):
        ''' Search for a single option by class. '''
        valid = []
        for opt in self.options:
            if isinstance(opt.payload, cls):
                valid.append(opt.payload)
        if len(valid) < 1:
            raise KeyError('no option found')
        if len(valid) > 1:
            raise KeyError('more than one option present')
        return valid[0]

packet.bind_layers(Head, ContactV4, version=4)
