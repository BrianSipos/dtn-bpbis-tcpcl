''' Items related to whole-bundle data.
'''
import logging
import cbor2
from . import formats
from .blocks import (PrimaryBlock, CanonicalBlock)
from sqlalchemy.sql.expression import false

LOGGER = logging.getLogger(__name__)


class Bundle(object):

    def __init__(self, data=None, cbor=None, blocks=None):
        # Definitive block ordering
        self._blocks = []
        # Map from block ID to Block
        self._block_id = {}
        self._block_type = {}

        if data is not None:
            self.decode_bytes(data)
        elif cbor is not None:
            self.decode_cbor(cbor)
        elif blocks is not None:
            self.set_blocks(blocks)

    def set_primary(self, block):
        if not isinstance(block, PrimaryBlock):
            raise TypeError()
        if len(self._blocks) == 0:
            self._blocks.append(None)
        self._blocks[0] = block
        self._block_id[0] = block

    def add_block(self):
        pass

    def set_blocks(self, blocks):
        if len(blocks) < 2:
            raise ValueError()

        block_id = {}
        block_type = {}
        for (blk_ix, blk) in enumerate(blocks):
            if blk_ix == 0:
                if not isinstance(blk, PrimaryBlock):
                    raise TypeError('First block must be a primary block')
            else:
                if not isinstance(blk, CanonicalBlock):
                    raise TypeError('Non-first block must be a canonical block')

                blk_id = blk.block_id
                if blk_id in block_id:
                    raise formats.DecodeError('Duplicate block_id value')
                block_id[blk_id] = blk

                blk_type = blk.type_code
                if blk_type not in block_type:
                    block_type[blk_type] = []
                block_type[blk_type].append(blk)

        for blk in blocks:
            blk.underlayer = self

        self._blocks = blocks
        self._block_id = block_id
        self._block_type = block_type

    def is_valid(self):
        if len(self._blocks) < 2:
            return False
        if 1 not in self._block_type:
            return False
        return True

    def encode_cbor(self):
        ''' Convert this bundle to a CBOR item.

        :return: The native bundle encoding.
        :rtype: array-like
        :raise RuntimeError: if the bundle is malformed.
        '''
        if not self.is_valid():
            raise RuntimeError('bundle is not valid')
        item = []
        for blk in self._blocks:
            blk.pre_encode()
            item.append(blk.encode_cbor())
        return item

    def decode_cbor(self, item):
        ''' Read this bundle from a CBOR item.

        :param item: The array-like item being decoded.
        :raise DecodeError: if there is any unrecoverable problem.
        '''
        blocks = []
        for (item_ix, subitem) in enumerate(item):
            if item_ix == 0:
                cls = PrimaryBlock
            else:
                cls = CanonicalBlock
            blk = cls(cbor=subitem)
            blocks.append(blk)
        self.set_blocks(blocks)
        for blk in blocks:
            blk.post_decode()

    def encode_bytes(self):
        ''' Encode the whole bundle as a bytestring.
        :return: The encoded bundle.
        '''
        item = self.encode_cbor()
        return cbor2.dumps(item)

    def decode_bytes(self, data):
        ''' Decode the whole bundle from a bytestring.
        :param data: The encoded bundle.
        '''
        item = cbor2.loads(data)
        self.decode_cbor(item)
