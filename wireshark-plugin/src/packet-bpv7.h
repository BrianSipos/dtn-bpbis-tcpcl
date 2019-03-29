
#ifndef WIRESHARK_PLUGIN_SRC_PACKET_BPV7_H_
#define WIRESHARK_PLUGIN_SRC_PACKET_BPV7_H_

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>
#include <glib.h>

/** Bundle CRC types.
 * Section 4.1.1.
 */
typedef enum {
    /// no CRC is present.
    BP_CRC_NONE = 0,
    /// a standard X-25 CRC-16 is present.
    BP_CRC_16 = 1,
    /// a standard CRC32C (Castagnoli) CRC-32 is present.
    BP_CRC_32 = 2,
} BundleCrcType;

/** Bundle processing control flags.
 * Section 4.1.3.
 */
typedef enum {
    /// bundle deletion status reports are requested.
    BP_BUNDLE_REQ_DELETION_REPORT = 0x1000,
    /// bundle delivery status reports are requested.
    BP_BUNDLE_REQ_DELIVERY_REPORT = 0x0800,
    /// bundle forwarding status reports are requested.
    BP_BUNDLE_REQ_FORWARDING_REPORT = 0x0400,
    /// bundle reception status reports are requested.
    BP_BUNDLE_REQ_RECEPTION_REPORT = 0x0100,
    /// bundle contains a Manifest block.
    BP_BUNDLE_CONTAINS_MANIFEST = 0x0080,
    /// status time is requested in all status reports.
    BP_BUNDLE_REQ_STATUS_TIME = 0x0040,
    /// user application acknowledgement is requested.
    BP_BUNDLE_USER_APP_ACK = 0x0020,
    /// bundle must not be fragmented.
    BP_BUNDLE_NO_FRAGMENT = 0x0004,
    /// payload is an administrative record.
    BP_BUNDLE_PAYLOAD_ADMIN = 0x0002,
    /// bundle is a fragment.
    BP_BUNDLE_IS_FRAGMENT = 0x0001,
} BundleProcessingFlag;

/** Block processing control flags.
 * Section 4.1.4.
 */
typedef enum {
    /// bundle must be deleted if block can't be processed.
    BP_BLOCK_DELETE_IF_NO_PROCESS = 0x08,
    /// transmission of a status report is requested if block can't be processed.
    BP_BLOCK_STATUS_IF_NO_PROCESS = 0x04,
    /// block must be removed from bundle if it can't be processed.
    BP_BLOCK_REMOVE_IF_NO_PROCESS = 0x02,
    /// block must be replicated in every fragment.
    BP_BLOCK_REPLICATE_IN_FRAGMENT = 0x01,
} BlockProcessingFlag;

/** Standard block type codes.
 * Section 4.2.3 and Section 4.3.
 */
typedef enum {
    /// Payload (data)
    BP_BLOCKTYPE_PAYLOAD = 1,
    /// Previous Node
    BP_BLOCKTYPE_PREV_NODE = 7,
    /// Bundle Age
    BP_BLOCKTYPE_BUNDLE_AGE = 8,
    /// Hop Count
    BP_BLOCKTYPE_HOP_COUNT = 9,
} BlockTypeCode;

/// Creation Timestamp used to correlate bundles
typedef struct {
    /// DTN timestamp
    gint64 dtntime;
    /// Sequence number
    guint64 seqno;
} bp_creation_ts_t;


/** Construct a new timestamp.
 */
bp_creation_ts_t * bp_creation_ts_new();

/** Function to match the GDestroyNotify signature.
 */
void bp_creation_ts_delete(gpointer ptr);

/** Function to match the GCompareDataFunc signature.
 */
gint bp_creation_ts_compare(gconstpointer a, gconstpointer b, gpointer user_data);

typedef struct {
    /// Bundle flags (assumed zero)
    guint64 flags;
    /// Destination EID
    tvbuff_t *dst_eid;
    /// Source EID
    tvbuff_t *src_eid;
    /// Report-to EID
    tvbuff_t *rep_eid;
    /// Creation Timestamp
    bp_creation_ts_t ts;
    /// CRC type code (assumed zero)
    BundleCrcType crc_type;
    /// Raw bytes of CRC field
    tvbuff_t *crc_field;
} bp_block_primary_t;

/** Construct a new object on the file allocator.
 */
bp_block_primary_t * bp_block_primary_new();

/** Function to match the GDestroyNotify signature.
 */
void bp_block_primary_delete(gpointer ptr);

typedef struct {
    /// The index of the block within the bundle.
    /// This is for internal bookkeeping, *not* the block number.
    guint64 index;

    const guint64 *type_code;
    const guint64 *block_number;
    guint64 flags;
    /// CRC type code (assumed zero)
    BundleCrcType crc_type;
    /// Raw bytes of CRC field
    tvbuff_t *crc_field;

    /// Type-specific data
    tvbuff_t *data;
} bp_block_canonical_t;

/** Construct a new object on the file allocator.
 * @param index The index of the block within the bundle.
 * The canonical index is always greater than zero.
 */
bp_block_canonical_t * bp_block_canonical_new(guint64 index);

/** Function to match the GDestroyNotify signature.
 */
void bp_block_canonical_delete(gpointer ptr);

/** Function to match the GCompareDataFunc signature.
 */
gint bp_block_compare_index(gconstpointer a, gconstpointer b, gpointer user_data);

/** Function to match the GCompareDataFunc signature.
 */
gint bp_block_compare_block_number(gconstpointer a, gconstpointer b, gpointer user_data);

typedef struct {
    /// Required primary block
    bp_block_primary_t *primary;
    /// Additional blocks in order (type bp_block_canonical_t)
    GSequence *blocks;
} bp_bundle_t;

/** Construct a new object on the file allocator.
 */
bp_bundle_t * bp_bundle_new();

/** Function to match the GDestroyNotify signature.
 */
void bp_bundle_delete(gpointer ptr);

/** Data supplied to each block sub-dissector.
 */
typedef struct {
    /// The overall bundle being decoded (so far)
    const bp_bundle_t *bundle;
    /// This block being decoded
    const bp_block_canonical_t *block;
} bp_dissector_data_t;

#endif /* WIRESHARK_PLUGIN_SRC_PACKET_BPV7_H_ */
