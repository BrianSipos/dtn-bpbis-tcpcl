
#ifndef WIRESHARK_PLUGIN_SRC_PACKET_BPV7_H_
#define WIRESHARK_PLUGIN_SRC_PACKET_BPV7_H_

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>
#include <epan/expert.h>
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
    BP_BUNDLE_REQ_DELETION_REPORT = 0x040000,
    /// bundle delivery status reports are requested.
    BP_BUNDLE_REQ_DELIVERY_REPORT = 0x020000,
    /// bundle forwarding status reports are requested.
    BP_BUNDLE_REQ_FORWARDING_REPORT = 0x010000,
    /// bundle reception status reports are requested.
    BP_BUNDLE_REQ_RECEPTION_REPORT = 0x004000,
    /// status time is requested in all status reports.
    BP_BUNDLE_REQ_STATUS_TIME = 0x000040,
    /// user application acknowledgement is requested.
    BP_BUNDLE_USER_APP_ACK = 0x000020,
    /// bundle must not be fragmented.
    BP_BUNDLE_NO_FRAGMENT = 0x000004,
    /// payload is an administrative record.
    BP_BUNDLE_PAYLOAD_ADMIN = 0x000002,
    /// bundle is a fragment.
    BP_BUNDLE_IS_FRAGMENT = 0x000001,
} BundleProcessingFlag;

/** Block processing control flags.
 * Section 4.1.4.
 */
typedef enum {
    /// block must be removed from bundle if it can't be processed.
    BP_BLOCK_REMOVE_IF_NO_PROCESS = 0x10,
    /// bundle must be deleted if block can't be processed.
    BP_BLOCK_DELETE_IF_NO_PROCESS = 0x04,
    /// transmission of a status report is requested if block can't be processed.
    BP_BLOCK_STATUS_IF_NO_PROCESS = 0x02,
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
    BP_BLOCKTYPE_PREV_NODE = 6,
    /// Bundle Age
    BP_BLOCKTYPE_BUNDLE_AGE = 7,
    /// Hop Count
    BP_BLOCKTYPE_HOP_COUNT = 10,
} BlockTypeCode;

/** Administrative record type codes.
 * Section 6.1.
 */
typedef enum {
    /// Bundle status report
    BP_ADMINTYPE_BUNDLE_STATUS = 1,
} AdminRecordTypeCode;

/** Bundle status report types.
 * These are not enumerated by the spec but are encoded separately
 * in Section 5.1.
 */
typedef enum {
    BP_STATUS_REPORT_RECEIVED,
    BP_STATUS_REPORT_FORWARDED,
    BP_STATUS_REPORT_DELIVERED,
    BP_STATUS_REPORT_DELETED,
} AdminBundleStatusInfoType;

/// The basic header structure of CBOR encoding
typedef struct {
    /// The start offset of this header
    gint start;
    /// The length of just this header
    gint length;
    /// The expert info object (if error)
    expert_field *error;

    /// Major type of this item (cbor_type)
    guint8 type_major;
    /// Minor type of this item
    guint8 type_minor;
    /// Either the encoded value or zero (with one-bit truncation possible)
    gint64 rawvalue;
} bp_cbor_head_t;

bp_cbor_head_t * bp_scan_cbor_head(tvbuff_t *tvb, gint start);

/** Function to match the GDestroyNotify signature.
 */
void bp_cbor_head_delete(gpointer ptr);

/// The same enumeration from libcbor-0.5
typedef enum cbor_type {
    CBOR_TYPE_UINT = 0, ///< positive integers
    CBOR_TYPE_NEGINT = 1, ///< negative integers
    CBOR_TYPE_BYTESTRING = 2, ///< byte strings
    CBOR_TYPE_STRING = 3, ///< text strings
    CBOR_TYPE_ARRAY = 4, ///< arrays
    CBOR_TYPE_MAP = 5, ///< maps
    CBOR_TYPE_TAG = 6, ///< tags
    CBOR_TYPE_FLOAT_CTRL = 7, ///< decimals and special values (true, false, nil, ...)
} cbor_type;

/// The same enumeration from libcbor-0.5
typedef enum {
    CBOR_CTRL_NONE = 0,
    CBOR_CTRL_FALSE = 20,
    CBOR_CTRL_TRUE = 21,
    CBOR_CTRL_NULL = 22,
    CBOR_CTRL_UNDEF = 23
} _cbor_ctrl;

/// The basic header structure of CBOR encoding
typedef struct {
    /// The start offset of this chunk
    gint start;
    /// The length of just this chunk
    gint head_length;
    /// The length of this chunk and its immediate definite data (i.e. strings)
    gint data_length;
    /// Additional blocks in order (type expert_field*)
    GSequence *errors;
    /// Additional blocks in order (type gint64)
    GSequence *tags;

    /// Major type of this block
    cbor_type type_major;
    /// Minor type of this item
    guint8 type_minor;
    /// The header-encoded value
    gint64 head_value;
} bp_cbor_chunk_t;

/** Scan for a tagged chunk of headers.
 *
 * @param tvb The TVB to read from.
 * @param start The offset with in @c tvb.
 * @return The chunk of data found, including any errors.
 */
bp_cbor_chunk_t * bp_scan_cbor_chunk(tvbuff_t *tvb, gint start);

void bp_cbor_chunk_mark_errors(packet_info *pinfo, proto_item *item, const bp_cbor_chunk_t *chunk);

/** Function to match the GDestroyNotify signature.
 */
void bp_cbor_chunk_delete(gpointer ptr);

/// DTN time with derived UTC time
typedef struct {
    /// DTN time
    guint64 dtntime;
    /// Converted to UTC
    nstime_t utctime;
} bp_dtn_time_t;

/// Creation Timestamp used to correlate bundles
typedef struct {
    /// Absolute time
    bp_dtn_time_t time;
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

/// EID encoding
typedef struct {
    /// Scheme ID number
    gint64 scheme;
    /// Derived URI text
    const char *uri;
} bp_nodeid_t;

/** Construct a new timestamp.
 */
bp_nodeid_t * bp_nodeid_new();

/** Function to match the GDestroyNotify signature.
 */
void bp_nodeid_delete(gpointer ptr);

typedef struct {
    /// Bundle flags (assumed zero)
    guint64 flags;
    /// Destination EID
    bp_nodeid_t *dst_nodeid;
    /// Source EID
    bp_nodeid_t *src_nodeid;
    /// Report-to EID
    bp_nodeid_t *rep_nodeid;
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
