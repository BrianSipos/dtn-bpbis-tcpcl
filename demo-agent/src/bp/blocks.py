''' Items related to per-block data.
'''
import enum
import logging
import struct
import cbor2
import crcmod
import scapy.packet
from . import formats

LOGGER = logging.getLogger(__name__)

# Map from CRC type to algorithm
CRC_DEFN = {
    1: {  # BPv7 CRC-16 X.25
        'func': crcmod.predefined.mkPredefinedCrcFun('x-25'),
        'encode': lambda val: struct.pack('>H', val)
    },
    2: {  # BPv7 CRC-32 Castagnoli
        'func': crcmod.predefined.mkPredefinedCrcFun('crc-32c'),
        'encode': lambda val: struct.pack('>L', val)
    },
}


class AbstractLayer(object):
    ''' An abstract data layer, either a block or a payload.

    Fields within the layer are identified by the `fields_desc` array.
    Fields can be accessed as direct attributes on this object.

    :param cbor: If not None, the block is read from this CBOR value.
    :param initvals: The initial field values.
    '''
    __slots__ = (
        'fields',
        'underlayer',
        'payload',
    )

    fields_desc = []

    def __init__(self, cbor=None, **initvals):
        object.__setattr__(self, 'underlayer', None)
        object.__setattr__(self, 'payload', None)

        fields = {}
        # Initialize field data
        if cbor is not None:
            self.decode_cbor(cbor)
        else:
            init_unused = set(initvals.keys())
            for defn in self.fields_desc:
                if defn.name in initvals:
                    val = initvals[defn.name]
                    init_unused.remove(defn.name)
                else:
                    val = defn.default
                fields[defn.name] = val
            object.__setattr__(self, 'fields', fields)
            if init_unused:
                raise RuntimeError('Unused initvals keys: {0}'.format(init_unused))

    def __getattr__(self, name):
        if name in self.fields:
            return self.fields[name]
        raise AttributeError()

    def __setattr__(self, name, value):
        if name in self.__slots__:
            object.__setattr__(self, name, value)
            return

        if name in self.fields:
            self.fields[name] = value

    def __div__(self, other):
        ''' Make another layer the payload of this one.
        '''
        self.add_payload(other)
        return self

    __truediv__ = __div__

    def add_payload(self, other):
        object.__setattr__(other, 'underlayer', self)
        object.__setattr__(self, 'payload', other)

    def pre_encode(self):
        ''' Perform activities prior to encoding.
        '''

    def encode_cbor(self):
        ''' Convert this block to a CBOR item.

        :return: The native block encoding.
        :rtype: array-like
        '''
        item = []
        for defn in self.fields_desc:
            data_val = self.fields[defn.name]
            try:
                cbor_val = defn.encode_cbor(data_val, self)
            except Exception as err:
                LOGGER.error('Failed to encode field "%s": %s', defn.name, err)
                raise
            print('encode', defn, data_val, cbor_val)
            if cbor_val is not formats.IGNORE:
                item.append(cbor_val)
        return item

    def decode_cbor(self, item):
        ''' Read this block from a CBOR item.

        :param item: The array-like item being decoded.
        :raise DecodeError: if there is any unrecoverable problem.
        '''
        fld_ix = 0
        for defn in self.fields_desc:
            cbor_val = item[fld_ix]
            data_val = defn.decode_cbor(cbor_val, self)
            if data_val is not formats.IGNORE:
                self.fields[defn.name] = data_val
                fld_ix += 1

    def post_decode(self):
        ''' Perform activities after decoding.
        '''


class AbstractBlock(AbstractLayer):
    ''' Represent an abstract block with CRC fields.
    The `underlayer` is the Bundle container.
    '''

    crc_type_name = 'crc_type'
    crc_field_name = 'crc_field'

    def _update_crc(self):
        ''' Update this block's CRC field from the current field data.
        '''
        if self.crc_type_name is None or self.crc_field_name is None:
            return

        crc_type = self.fields[self.crc_type_name]
        if crc_type == 0:
            crc_value = None
        else:
            defn = CRC_DEFN[crc_type]
            # Encode with a zero-valued CRC field
            self.fields[self.crc_field_name] = defn['encode'](0)
            pre_crc = cbor2.dumps(self.encode_cbor())
            crc_int = defn['func'](pre_crc)
            crc_value = defn['encode'](crc_int)
        self.fields[self.crc_field_name] = crc_value

    def fuzz(self):
        ''' Perform randomization on this block's data.
        '''
        for defn in self.fields_desc:
            if self.fields[defn.name] is not None:
                self.fields[defn.name] = defn.randval()

    def pre_encode(self):
        self._update_crc()


class PrimaryBlock(AbstractBlock):
    ''' The primary block definition '''

    @enum.unique
    class Flag(enum.IntFlag):
        ''' Bundle flags.
        Flags must be in LSbit-first order.
        '''
        BUNDLE_IS_FRAGMENT = 2 ** 0
        PAYLOAD_IS_ADMIN = 2 ** 1
        BUNDLE_MUST_NOT_BE_FRAGMENTED = 2 ** 2
        USER_APP_ACK_REQUESTED = 2 ** 5
        STATUS_TIME_REQUESTED = 2 ** 6

    fields_desc = (
        formats.UintField('bp_version', default=7),
        formats.FlagsField('bundle_flags', default=0, flags=Flag),
        formats.UintField('crc_type', default=0),
        formats.EidField('destination'),
        formats.EidField('source'),
        formats.EidField('report_to'),
        formats.TimestampField('creation_timestamp'),
        formats.UintField('lifetime', default=0),
        formats.ConditionalField(
            formats.UintField('fragment_offset', default=0),
            lambda block: block.bundle_flags & PrimaryBlock.Flag.BUNDLE_IS_FRAGMENT
        ),
        formats.ConditionalField(
            formats.UintField('total_app_data_len', default=0),
            lambda block: block.bundle_flags & PrimaryBlock.Flag.BUNDLE_IS_FRAGMENT
        ),
        formats.ConditionalField(
            formats.BstrField('crc_value'),
            lambda block: block.crc_type != 0
        ),
    )


class CanonicalBlock(AbstractBlock):
    ''' The canonical block definition with a payload underlayer.
    '''
    _type_class = {}
    _class_type = {}
    _payload_index = 5

    @enum.unique
    class Flag(enum.IntFlag):
        ''' Block flags.
        Flags must be in LSbit-first order.
        '''

    fields_desc = (
        formats.UintField('type_code', default=None),
        formats.UintField('block_id', default=None),
        formats.FlagsField('block_flags', default=0, flags=Flag),
        formats.UintField('crc_type', default=0),
        formats.ConditionalField(
            formats.BstrField('crc_value'),
            lambda block: block.crc_type != 0
        ),
    )

    @staticmethod
    def bind_block_type(pyld, type_code):
        ''' Bind a block-type-specific class handler.
        '''
        CanonicalBlock._type_class[type_code] = pyld
        CanonicalBlock._class_type[pyld] = type_code

    def encode_cbor(self):
        if self.payload is None:
            raise RuntimeError('cannot encode without canonical payload')
        self.fields['type_code'] = CanonicalBlock._class_type[self.payload.__class__]
        pyld_cbor = self.payload.encode_cbor()

        item = AbstractBlock.encode_cbor(self)
        item.insert(CanonicalBlock._payload_index, pyld_cbor)
        return item

    def decode_cbor(self, item):
        pyld_cbor = item[CanonicalBlock._payload_index]
        del item[CanonicalBlock._payload_index]

        AbstractBlock.decode_cbor(self, item)
        cls = CanonicalBlock._type_class[self.fields['type_code']]
        self.add_payload(cls(cbor=pyld_cbor))


class Payload(AbstractLayer):
    ''' A special case layer which is undecoded CBOR item storage.
    '''
    __slots__ = ('item',) + AbstractLayer.__slots__

    def __init__(self, cbor=None):
        AbstractLayer.__init__(self)
        self.item = cbor

    def encode_cbor(self):
        return self.item

    def decode_cbor(self, item):
        self.item = item
CanonicalBlock.bind_block_type(Payload, type_code=1)

class AdminRecord(AbstractLayer):
    pass
