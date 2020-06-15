''' Field types for BP.
'''
import cbor2
from scapy import fields, volatile, packet

class IgnoreItem(object):
    ''' Exception to indicate ignoring the value. '''

IGNORE = IgnoreItem()

class DecodeError(RuntimeError):
    ''' Signal an error in CBOR decoding. '''

class CborField(object):
    ''' Abstract base type.

    :param str name: The unique field name.
    :param default: Default/initial value.
    '''

    def __init__(self, name, default=IGNORE):
        self.name = str(name)
        self.default = default

    def encode_cbor(self, data_val, block):
        ''' Encode this field to a CBOR item.

        :param data_val: The internal data value.
        :param block: The block context.
        :return: The CBOR item.
        :rtype: A value or :py:obj:`IGNORE`.
        '''
        return data_val

    def decode_cbor(self, cbor_val, block):
        ''' Decode this field from a CBOR item.

        :param data_val: The CBOR item value.
        :param block: The block context.
        :return: The internal data value.
        :rtype: A value or :py:obj:`IGNORE`.
        '''
        return cbor_val


class ConditionalField(object):

    def __init__(self, fld, cond):
        self.fld = fld
        self.cond = cond

    def __getattr__(self, name):
        return getattr(self.fld, name)

    def encode_cbor(self, data_val, block):
        if not self.cond(block):
            return IGNORE
        return self.fld.encode_cbor(data_val, block)

    def decode_cbor(self, cbor_val, block):
        if not self.cond(block):
            return IGNORE
        return self.fld.decode_cbor(cbor_val, block)

class UintField(CborField):
    ''' A field which must be 'uint' type.

    :param maxval: The maximum value allowed in this field.
        Warnings will be output if the actual value is above this limit
    '''

    def __init__(self, name, default=IGNORE, maxval=None):
        CborField.__init__(self, name, default)
        if maxval is None:
            maxval = 2 ** 64 - 1
        self.maxval = maxval

    def encode_cbor(self, data_val, block):
        if not isinstance(data_val, (int,)):
            return cbor2.undefined
        return int(data_val)

    def decode_cbor(self, cbor_val, block):
        if not isinstance(cbor_val, (int,)):
            raise DecodeError()
        return int(cbor_val)

    def randval(self):
        return volatile.RandNum(0, self.maxval)


class TstrField(CborField):
    ''' Allow only CBOR 'tstr' value.
    '''

    def __init__(self, name, default=''):
        CborField.__init__(self, name, default)

    def encode_cbor(self, data_val, block):
        return str(data_val)

    def decode_cbor(self, cbor_val, block):
        if not isinstance(cbor_val, [str]):
            raise DecodeError()
        return str(cbor_val)

    def randval(self):
        return volatile.RandString(1000)


class BstrField(CborField):
    ''' Allow only CBOR 'bstr' value.
    '''

    def __init__(self, name, default=b''):
        CborField.__init__(self, name, default)

    def encode_cbor(self, data_val, block):
        return bytes(data_val)

    def decode_cbor(self, cbor_val, block):
        if not isinstance(cbor_val, [str]):
            raise DecodeError()
        return bytes(cbor_val)

    def randval(self):
        return volatile.RandBin(1000)


class FlagsField(UintField):

    def __init__(self, name, default, flags):
        maxval = 0
        for val in flags:
            maxval |= int(val)
        self.flags = flags

        UintField.__init__(self, name, default, maxval)


class EidField(TstrField):

    def randval(self):
        nodename = volatile.RandString(50)
        servname = volatile.RandString(50)
        return 'dtn://{0}/{1}'.format(nodename, servname)


class TimestampField(CborField):

    def encode_cbor(self, data_val, _block):
        if data_val is None:
            return [0, 0]
        return data_val

    def randval(self):
        return [
            volatile.RandNum(-(2**16), (2**16)),
            volatile.RandNum(0, 100)
        ]
