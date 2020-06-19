''' Items related to per-block data.
'''
import datetime
import calendar
import enum
import logging
import struct
import urllib
import cbor2
import crcmod
from scapy import volatile
from scapy.config import conf
import scapy.packet
from scapy_cbor.packets import (CborArray, CborItem)
from scapy_cbor.fields import (
    CborField, BstrField, ConditionalField, FlagsField, UintField,
    PacketField, PacketListField
)
from builtins import isinstance

LOGGER = logging.getLogger(__name__)


class EidField(CborField):
    ''' A structured representation of an Endpoint ID.
    Only specific URI schemes are encodable.
    '''

    @enum.unique
    class TypeCode(enum.IntFlag):
        ''' EID scheme codes.
        Flags must be in LSbit-first order.
        '''
        dtn = 1
        ipn = 2

    def i2m(self, pkt, val):
        if val is None or val == 'dtn:none':
            return [EidField.TypeCode.dtn, 0]

        parts = urllib.parse.urlparse(val)
        try:
            scheme_type = EidField.TypeCode[parts[0]]
        except KeyError:
            raise ValueError('No type code for scheme "{}"'.format(parts[0]))
        ssp = '//{0}{1}'.format(parts[1], parts[2])
        return [scheme_type, ssp]

    def m2i(self, pkt, val):
        if val is None:
            return None
        scheme_type = val[0]
        ssp = val[1]
        return '{0}:{1}'.format(
            EidField.TypeCode(scheme_type).name,
            ssp
        )

    def randval(self):
        nodename = volatile.RandString(50)
        servname = volatile.RandString(50)
        return 'dtn://{0}/{1}'.format(nodename, servname)


class TimestampField(CborField):
    ''' A structured representation of an DTN Timestamp.
    The timestamp is a two-tuple of (creation time, sequence number)
    The creation time portion is automatically converted from a
    :py:cls:`datetime.datetime` object.
    '''

    UTC = datetime.timezone(datetime.timedelta(0))
    #: Epoch reference for DTN Time
    DTN_EPOCH = datetime.datetime(2000, 1, 1, 0, 0, 0, 0, UTC)

    @classmethod
    def datetime_to_dtntime(cls, val):
        return int((val - cls.DTN_EPOCH).total_seconds())

    @classmethod
    def dtntime_to_datetime(cls, val):
        return datetime.timedelta(seconds=val) + cls.DTN_EPOCH

    @classmethod
    def ingest_dtntime(cls, val):
        if isinstance(val, int):
            return val
        elif isinstance(val, datetime.datetime):
            return TimestampField.datetime_to_dtntime(val)
        elif isinstance(val, (str,)):
            return TimestampField.datetime_to_dtntime(datetime.datetime.fromisoformat(val))
        else:
            return None

    def i2h(self, pkt, x):
        if x is None:
            return ''
        return [
            TimestampField.dtntime_to_datetime(x[0]).isoformat(),
            x[1]
        ]

    def h2i(self, pkt, x):
        if not x:
            return None
        if len(x) == 2:
            return [
                TimestampField.ingest_dtntime(x[0]),
                x[1]
            ]

        return [
            TimestampField.ingest_dtntime(x),
            0
        ]

    def i2m(self, pkt, val):
        if val is None:
            return [0, 0]
        return val

    def randval(self):
        return [
            volatile.RandNum(-(2 ** 16), (2 ** 16)),
            volatile.RandNum(0, 100)
        ]


class AbstractBlock(CborArray):
    ''' Represent an abstract block with CRC fields.

    .. py:attribute:: crc_type_name
        The name of the CRC-type field.
    .. py:attribute:: crc_value_name
        The name of the CRC-value field.
    '''

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

    crc_type_name = 'crc_type'
    crc_value_name = 'crc_value'

    def update_crc(self):
        ''' Update this block's CRC field from the current field data
        only if the current CRC (field not default) value is None.
        '''
        if self.crc_type_name is None or self.crc_value_name is None:
            return

        crc_type = self.getfieldval(self.crc_type_name)
        if crc_type == 0:
            crc_value = None
        else:
            crc_value = self.fields.get(self.crc_value_name)
            if crc_value is None:
                defn = AbstractBlock.CRC_DEFN[crc_type]
                # Encode with a zero-valued CRC field
                self.fields[self.crc_value_name] = defn['encode'](0)
                pre_crc = cbor2.dumps(self.build())
                print('pre_crc', pre_crc)
                crc_int = defn['func'](pre_crc)
                crc_value = defn['encode'](crc_int)

        self.fields[self.crc_value_name] = crc_value


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
        UintField('bp_version', default=7),
        FlagsField('bundle_flags', default=0, flags=Flag),
        UintField('crc_type', default=0),
        EidField('destination'),
        EidField('source'),
        EidField('report_to'),
        TimestampField('creation_timestamp'),
        UintField('lifetime', default=0),
        ConditionalField(
            UintField('fragment_offset', default=0),
            lambda block: block.bundle_flags & PrimaryBlock.Flag.BUNDLE_IS_FRAGMENT
        ),
        ConditionalField(
            UintField('total_app_data_len', default=0),
            lambda block: block.bundle_flags & PrimaryBlock.Flag.BUNDLE_IS_FRAGMENT
        ),
        ConditionalField(
            BstrField('crc_value'),
            lambda block: block.crc_type != 0
        ),
    )


class CanonicalBlock(AbstractBlock):
    ''' The canonical block definition with a type-specific payload.

    Any payload of this block is encoded as the "data" field when building
    and decoded from the "data" field when dissecting.
    '''

    @enum.unique
    class Flag(enum.IntFlag):
        ''' Block flags.
        Flags must be in LSbit-first order.
        '''

    fields_desc = (
        UintField('type_code', default=None),
        UintField('block_num', default=None),
        FlagsField('block_flags', default=0, flags=Flag),
        UintField('crc_type', default=0),
        BstrField('data', default=None),  # block-type-specific data here
        ConditionalField(
            BstrField('crc_value'),
            lambda block: block.crc_type != 0
        ),
    )

    def self_build(self, field_pos_list=None):
        # Embed payload as field overload
        if (self.overloaded_fields.get('data') is None
            and not isinstance(self.payload, scapy.packet.NoPayload)):
            pay_type = CanonicalBlock.__data_classes[type(self.payload)]
            pay_data = cbor2.dumps(self.payload.do_build())
            self.overloaded_fields['data'] = pay_data
            self.overloaded_fields['type_code'] = pay_type

        return AbstractBlock.self_build(self, field_pos_list)

    def do_build_payload(self):
        # Payload is handled by self_build
        return b''

    def post_dissect(self, s):
        # Extract payload from fields
        pay_type = self.fields.get('type_code')
        pay_data = self.fields.get('data')
        if (pay_data is not None and pay_type is not None):
            try:
                cls = CanonicalBlock.__data_types[pay_type]
            except KeyError:
                cls = None
            if cls is not None:
                try:
                    pay = cls(pay_data)
                    self.add_payload(pay)
                except Exception:
                    if conf.debug_dissector:
                        raise

        return AbstractBlock.post_dissect(self, s)

    # Block-specific data handling classes
    __data_types = {}
    __data_classes = {}

    @staticmethod
    def bind_type(type_code):
        ''' Bind a block-type-specific packet-class handler.
        '''

        def func(cls):
            if type_code in CanonicalBlock.__data_types:
                raise ValueError('Block type code {} is already registered'.format(type_code))
            if cls in CanonicalBlock.__data_classes:
                raise ValueError('Block type class {} is already registered'.format(cls))
            CanonicalBlock.__data_types[type_code] = cls
            CanonicalBlock.__data_classes[cls] = type_code
            return cls

        return func


class Bundle(CborArray):
    ''' An entire decoded bundle contents.

    Bundles with administrative records are handled specially in that the
    AdminRecord object will be made a (scapy) payload of the "payload block"
    which is block type code 1.
    '''

    fields_desc = (
        PacketField('primary', default=None, cls=PrimaryBlock),
        PacketListField('blocks', default=[], cls=CanonicalBlock),
    )

    def self_build(self, field_pos_list=None):
        # Special handling for admin payload
        for blk in self.blocks:
            if isinstance(blk.payload, AdminRecord):
                self.primary.bundle_flags |= PrimaryBlock.Flag.PAYLOAD_IS_ADMIN
                blk.type_code = 1
                blk.data = bytes(blk.payload)

        return AbstractBlock.self_build(self, field_pos_list)

    def post_dissect(self, s):
        # Special handling for admin payload
        if self.primary and self.primary.bundle_flags & PrimaryBlock.Flag.PAYLOAD_IS_ADMIN:
            for blk in self.blocks:
                if blk.type_code == 1 and blk.data is not None:
                    pay = AdminRecord(blk.data)
                    blk.add_payload(pay)

        return CborArray.post_dissect(self, s)

    def update_all_crc(self):
        ''' Update all CRC fields in this bundle which are not yet set.
        '''
        if self.primary:
            self.primary.update_crc()
        for blk in self.blocks:
            blk.update_crc()


@CanonicalBlock.bind_type(6)
class PreviousNodeBlockData(CborItem):
    ''' Block data from BPbis Section 4.3.1.
    '''
    fields_desc = (
        EidField('node'),
    )


@CanonicalBlock.bind_type(7)
class BundleAgeBlockData(CborItem):
    ''' Block data from BPbis Section 4.3.2.
    '''
    fields_desc = (
        UintField('age'),
    )


@CanonicalBlock.bind_type(10)
class HopCountBlockData(CborArray):
    ''' Block data from BPbis Section 4.3.3.
    '''
    fields_desc = (
        UintField('limit'),
        UintField('count'),
    )


class AdminRecord(CborArray):
    ''' An administrative record bundle payload.
    This is handled specially because it needs a primary block flag
    to indicate its presence.
    '''

    fields_desc = (
        UintField('type_code'),
        # Type-specific data as scapy payload injected into this array
        # as a single value, not appended to the array
    )

    def do_build_payload(self):
        # Guarantee a two-element self array
        if isinstance(self.payload, scapy.packet.NoPayload):
            pay = [None]
        else:
            pay = [self.payload.build()]
        return pay

    def do_dissect_payload(self, s):
        # Remove admin array wrap
        s = s[0]
        return CborArray.do_dissect_payload(self, s)

    @staticmethod
    def bind_type(type_code):
        ''' Bind a admin record type packet-class handler.
        :param int type_code: The record type code to bind as.
        '''

        def func(cls):
            scapy.packet.bind_layers(AdminRecord, cls, type_code=type_code)
            return cls

        return func


# Special case for some unknown item
AdminRecord.bind_type(None)(CborItem)


@AdminRecord.bind_type(1)
class StatusReport(CborArray):
    field_desc = (
        CborField('status_info'),
        CborField('reason_code'),
        EidField('source'),
        UintField('fragment_offset', default=0),
        UintField('total_app_data_len', default=0),
    )

