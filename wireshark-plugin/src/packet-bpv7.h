
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
    BP_BLOCKTYPE_INVALID = 0,
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

/** Endpoint ID scheme encodings.
 */
typedef enum {
    EID_SCHEME_DTN = 1,
    EID_SCHEME_IPN = 2,
} EidScheme;

/// Metadata from a Endpoint ID
typedef struct {
    /// Scheme ID number
    gint64 scheme;
    /// Derived URI text
    const char *uri;
} bp_eid_t;

/** Construct a new timestamp.
 */
bp_eid_t * bp_eid_new();

/** Function to match the GDestroyNotify signature.
 */
void bp_eid_delete(gpointer ptr);

/** Function to match the GCompareFunc signature.
 */
gboolean bp_eid_equal(gconstpointer a, gconstpointer b);

/// Metadata extracted from the primary block
typedef struct {
    /// Bundle flags (assumed zero)
    guint64 flags;
    /// Destination EID
    bp_eid_t *dst_eid;
    /// Source NID
    bp_eid_t *src_nodeid;
    /// Report-to NID
    bp_eid_t *rep_nodeid;
    /// Creation Timestamp
    bp_creation_ts_t ts;
    /// Optional fragment start offset
    guint64 *frag_offset;
    /// Optional bundle total length
    guint64 *total_len;
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
    /// Type of this block
    const guint64 *type_code;
    /// Unique identifier for this block
    const guint64 *block_number;
    /// All flags on this block
    guint64 flags;
    /// CRC type code (assumed zero)
    BundleCrcType crc_type;
    /// Raw bytes of CRC field
    tvbuff_t *crc_field;
    /// Type-specific data, unencoded
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

/// Metadata extracted per-bundle
typedef struct {
    /// Index of the frame
    guint32 frame_num;
    /// Required primary block
    bp_block_primary_t *primary;
    /// Additional blocks in order (type bp_block_canonical_t)
    GSequence *blocks;
    /// Map from block type code (guint64) to sequence (GPtrArray) of
    /// pointers to block of that type (bp_block_canonical_t owned by #blocks)
    GHashTable *block_types;
} bp_bundle_t;

/** Construct a new object on the file allocator.
 */
bp_bundle_t * bp_bundle_new();

/** Function to match the GDestroyNotify signature.
 */
void bp_bundle_delete(gpointer ptr);

/// Identification of an individual bundle
typedef struct {
    /// Pointer to an external Source Node ID
    bp_eid_t *src;
    /// Pointer to an external Creation Timestamp
    bp_creation_ts_t *ts;
    /// Pointer to external optional fragment start offset
    guint64 *frag_offset;
    /// Pointer to external optional bundle total length
    guint64 *total_len;
} bp_bundle_ident_t;

/** Construct a new object on the file allocator.
 */
bp_bundle_ident_t * bp_bundle_ident_new(bp_eid_t *src, bp_creation_ts_t *ts, guint64 *off, guint64 *len);

/** Function to match the GDestroyNotify signature.
 */
void bp_bundle_ident_delete(gpointer ptr);

/** Function to match the GCompareFunc signature.
 */
gboolean bp_bundle_ident_equal(gconstpointer a, gconstpointer b);

/** Function to match the GHashFunc signature.
 */
guint bp_bundle_ident_hash(gconstpointer key);

/** Extract an Endpoint ID.
 *
 * @param tree The tree to write items under.
 * @param hfindex The root item field.
 * @param pinfo Packet info to update.
 * @param tvb Buffer to read from.
 * @param[in,out] offset Starting offset within @c tvb.
 * @param[out] eid If non-null, the EID to write to.
 * @return The new tree item.
 */
proto_item * proto_tree_add_cbor_eid(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, gint *offset, bp_eid_t *eid);

/// Metadata for an entire conversation
typedef struct {
    /// Map from a bundle ID (bp_bundle_ident_t) to bundle (bp_bundle_t)
    GHashTable *bundles;
} bp_history_t;

/** Data supplied to each block sub-dissector.
 */
typedef struct {
    /// The overall bundle being decoded (so far)
    const bp_bundle_t *bundle;
    /// This block being decoded
    const bp_block_canonical_t *block;
} bp_dissector_data_t;

#endif /* WIRESHARK_PLUGIN_SRC_PACKET_BPV7_H_ */
