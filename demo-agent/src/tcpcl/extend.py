''' Session and Transfer extension type definitions. '''
from scapy import fields, packet
from . import formats
from .messages import TransferExtendHeader

class TransferTotalLength(formats.NoPayloadPacket):
    ''' Identify total transfer (bundle) length. '''
    fields_desc = [
        formats.UInt64Field('total_length', default=None),
    ]

packet.bind_layers(TransferExtendHeader, TransferTotalLength, type=0x1)
