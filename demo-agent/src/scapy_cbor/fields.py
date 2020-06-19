''' Extend SCAPY field interface for CBOR encoding.
'''
import logging
import cbor2
from scapy import fields, volatile

LOGGER = logging.getLogger(__name__)


class DecodeError(RuntimeError):
    ''' Signal an error in CBOR decoding. '''


class CborField(fields.Field):
    ''' Abstract base type.

    :param str name: The unique field name.
    :param default: Default/initial value.
    '''

    def __init__(self, name, default=None):
        fields.Field.__init__(self, name, default, '!s')

    def addfield(self, pkt, s, val):
        ''' Augmented signature for `s` as CBOR array instead of bytes.
        '''
        s.append(self.i2m(pkt, val))
        return s

    def getfield(self, pkt, s):
        ''' Augmented signature for `s` as CBOR array instead of bytes.
        '''
        item = s.pop(0)
        val = self.m2i(pkt, item)
        return (s, val)

    def i2m(self, pkt, val):
        ''' Encode this field to a CBOR item.

        :param pkt: The packet (container) context.
        :param val: The internal data value.
        :return: The CBOR item.
        :rtype: A value or :py:obj:`IGNORE`.
        '''
        return val

    def m2i(self, pkt, val):
        ''' Decode this field from a CBOR item.

        :param pkt: The packet (container) context.
        :param val: The CBOR item value.
        :return: The internal data value.
        :rtype: A value or :py:obj:`IGNORE`.
        '''
        return val


ConditionalField = fields.ConditionalField


class PacketField(CborField):
    ''' Similar to :py:cls:`scapy.fields.PacketField` but
    for CBOR encoding.
    '''
    __slots__ = ["cls"]
    holds_packets = 1

    def __init__(self, name, default, cls):
        CborField.__init__(self, name, default)
        self.cls = cls

    def i2m(self, pkt, val):
        if val is None:
            return None
        return val.build()

    def m2i(self, pkt, val):
        if val is None:
            return None
        obj = self.cls()
        obj.dissect(val)
        return obj


class PacketListField(PacketField):
    ''' Similar to :py:cls:`scapy.fields.PacketListField` but
    for CBOR encoding.
    '''
    islist = 1

    def getfield(self, pkt, s):
        ''' Augmented signature for `s` as CBOR array instead of bytes.
        '''
        count = len(s)

        lst = []
        for _ix in range(0, count):
            subitem = s.pop(0)
            obj = self.m2i(pkt, subitem)
            lst.append(obj)
        return (s, lst)

    def addfield(self, pkt, s, val):
        ''' Augmented signature for `s` as CBOR array instead of bytes.
        '''
        for obj in val:
            subitem = self.i2m(pkt, obj)
            s.append(subitem)
        return s


class UintField(CborField):
    ''' A field which must be 'uint' type.

    :param maxval: The maximum value allowed in this field.
        Warnings will be output if the actual value is above this limit
    '''
    __slots__ = [
        'maxval',
    ]

    def __init__(self, name, default=None, maxval=None):
        CborField.__init__(self, name, default)
        if maxval is None:
            maxval = 2 ** 64 - 1
        self.maxval = maxval

    def i2m(self, pkt, val):
        try:
            return int(val)
        except TypeError:
            return None

    def m2i(self, pkt, val):
        try:
            return int(val)
        except TypeError:
            return None

    def randval(self):
        return volatile.RandNum(0, self.maxval)


class FlagsField(UintField):
    ''' An integer containing enumerated flags.

    :param flags: Available flags for the field.
    :type flags: enum.IntFlag -like
    '''
    __slots__ = (
        'flags',
    )

    def __init__(self, name, default, flags):
        maxval = 0
        for val in flags:
            maxval |= int(val)
        self.flags = flags

        UintField.__init__(self, name, default, maxval)


class TstrField(CborField):
    ''' Allow only CBOR 'tstr' value.
    '''

    def __init__(self, name, default=None):
        CborField.__init__(self, name, default)

    def i2m(self, pkt, val):
        try:
            return str(val)
        except TypeError:
            return None

    def m2i(self, pkt, val):
        try:
            return str(val)
        except TypeError:
            return None

    def randval(self):
        return volatile.RandString(1000)


class BstrField(CborField):
    ''' Allow only CBOR 'bstr' value.
    '''

    def __init__(self, name, default=None):
        CborField.__init__(self, name, default)

    def i2m(self, pkt, val):
        try:
            return bytes(val)
        except TypeError:
            return None

    def m2i(self, pkt, val):
        try:
            return bytes(val)
        except TypeError:
            return None

    def randval(self):
        return volatile.RandBin(1000)


class CborEncodedField(BstrField):
    ''' An encoded CBOR data item within a 'bstr'.
    '''

    def i2m(self, pkt, val):
        try:
            enc = cbor2.dumps(val)
            return enc
        except cbor2.CBOREncodeError:
            return None

    def m2i(self, pkt, val):
        try:
            dec = cbor2.loads(val)
            return dec
        except cbor2.CBORDecodeError:
            return None
