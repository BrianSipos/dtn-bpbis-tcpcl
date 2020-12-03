#include "packet-bpv7.h"
#include "bp_cbor.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <wsutil/crc16.h>
#include <wsutil/crc32.h>
#include <stdio.h>
#include <inttypes.h>

#if WIRESHARK_APIVERS >= 3
#include <ws_version.h>
#else
#include <config.h>
#define WIRESHARK_VERSION_MAJOR VERSION_MAJOR
#define WIRESHARK_VERSION_MINOR VERSION_MINOR
#endif

/// Protocol preferences and defaults
static gboolean bp_compute_crc = TRUE;

/// Protocol handles
static int proto_bp = -1;
/// Protocol-level data
static bp_history_t *bp_history = NULL;

/// Dissect opaque CBOR parameters/results
static dissector_table_t dissect_media = NULL;
/// Extension sub-dissectors
static dissector_table_t block_dissectors = NULL;
static dissector_table_t payload_dissectors = NULL;
static dissector_table_t admin_dissectors = NULL;

static const val64_string eid_schemes[] = {
    {EID_SCHEME_DTN, "dtn"},
    {EID_SCHEME_IPN, "ipn"},
    {0, NULL},
};

static const val64_string crc_vals[] = {
    {BP_CRC_NONE, "None"},
    {BP_CRC_16, "CRC-16"},
    {BP_CRC_32, "CRC-32C"},
    {0, NULL},
};

static const val64_string blocktype_vals[] = {
    {BP_BLOCKTYPE_PAYLOAD, "Payload"},
    {BP_BLOCKTYPE_PREV_NODE, "Previous Node"},
    {BP_BLOCKTYPE_BUNDLE_AGE, "Bundle Age"},
    {BP_BLOCKTYPE_HOP_COUNT, "Hop Count"},
    {0, NULL},
};

typedef struct {
    /// Type of block
    guint64 type_code;
    /// Limit on total count
    guint64 limit;
} blocktype_limit;
/// Block type count limits
static const blocktype_limit blocktype_limits[] = {
    {BP_BLOCKTYPE_PAYLOAD, 1},
    {BP_BLOCKTYPE_PREV_NODE, 1},
    {BP_BLOCKTYPE_BUNDLE_AGE, 1},
    {BP_BLOCKTYPE_HOP_COUNT, 1},
    // Mandatory last row
    {BP_BLOCKTYPE_INVALID, 0},
};

static const val64_string admin_type_vals[] = {
    {BP_ADMINTYPE_BUNDLE_STATUS, "Bundle Status Report"},
    {0, NULL},
};

static const val64_string status_report_reason_vals[] = {
    {0, "No additional information"},
    {1, "Lifetime expired"},
    {2, "Forwarded over unidirectional link"},
    {3, "Transmission canceled"},
    {4, "Depleted storage"},
    {5, "Destination endpoint ID unintelligible"},
    {6, "No known route to destination from here"},
    {7, "No timely contact with next node on route"},
    {8, "Block unintelligible"},
    {9, "Hop limit exceeded"},
    {0, NULL},
};

static int hf_bundle = -1;
static int hf_bundle_head = -1;
static int hf_bundle_break = -1;
static int hf_block = -1;
static int hf_crc_field_int16 = -1;
static int hf_crc_field_int32 = -1;
static int hf_crc_actual_int16 = -1;
static int hf_crc_actual_int32 = -1;

static int hf_time_dtntime = -1;
static int hf_time_utctime = -1;

static int hf_create_ts_time = -1;
static int hf_create_ts_seqno = -1;

static int hf_eid_scheme = -1;
static int hf_eid_dtn_ssp_code = -1;
static int hf_eid_dtn_ssp_text = -1;
static int hf_eid_ipn_node = -1;
static int hf_eid_ipn_service = -1;
static int hf_eid_as_uri = -1;

static int hf_primary_version = -1;
static int hf_primary_bundle_flags = -1;
static int hf_primary_bundle_flags_deletion_report = -1;
static int hf_primary_bundle_flags_delivery_report = -1;
static int hf_primary_bundle_flags_forwarding_report = -1;
static int hf_primary_bundle_flags_reception_report = -1;
static int hf_primary_bundle_flags_req_status_time = -1;
static int hf_primary_bundle_flags_user_app_ack = -1;
static int hf_primary_bundle_flags_no_fragment = -1;
static int hf_primary_bundle_flags_payload_admin = -1;
static int hf_primary_bundle_flags_is_fragment = -1;
static int hf_primary_crc_type = -1;
static int hf_primary_dst_eid = -1;
static int hf_primary_src_nodeid = -1;
static int hf_primary_report_nodeid = -1;
static int hf_primary_create_ts = -1;
static int hf_primary_lifetime = -1;
static int hf_primary_lifetime_exp = -1;
static int hf_primary_expire_ts = -1;
static int hf_primary_frag_offset = -1;
static int hf_primary_total_length = -1;
static int hf_primary_crc_field = -1;

static int hf_bundle_ident = -1;

static int hf_canonical_type_code = -1;
static int hf_canonical_block_num = -1;
static int hf_canonical_block_flags = -1;
static int hf_canonical_block_flags_delete_no_process = -1;
static int hf_canonical_block_flags_status_no_process = -1;
static int hf_canonical_block_flags_remove_no_process = -1;
static int hf_canonical_block_flags_replicate_in_fragment = -1;
static int hf_canonical_crc_type = -1;
static int hf_canonical_data = -1;
static int hf_canonical_crc_field = -1;

static int hf_previous_node_nodeid = -1;
static int hf_bundle_age_time = -1;
static int hf_hop_count_limit = -1;
static int hf_hop_count_current = -1;

static int hf_admin_record = -1;
static int hf_admin_record_type = -1;
static int hf_status_rep = -1;
static int hf_status_rep_status_info = -1;
static int hf_status_assert_val = -1;
static int hf_status_assert_time = -1;
static int hf_status_rep_received = -1;
static int hf_status_rep_forwarded = -1;
static int hf_status_rep_delivered = -1;
static int hf_status_rep_deleted = -1;
static int hf_status_rep_reason_code = -1;
static int hf_status_rep_subj_src_nodeid = -1;
static int hf_status_rep_subj_ts = -1;
static int hf_status_rep_subj_frag_offset = -1;
static int hf_status_rep_subj_payload_len = -1;
static int hf_status_rep_subj_ident = -1;
static int hf_status_rep_subj_ref = -1;

/// Field definitions
static hf_register_info fields[] = {
    {&hf_bundle, {"Bundle Protocol Version 7", "bpv7", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_bundle_head, {"Indefinite Array", "bpv7.bundle_head", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_bundle_break, {"Indefinite Break", "bpv7.bundle_break", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_block, {"Block", "bpv7.block", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_crc_field_int16, {"CRC Field Integer", "bpv7.crc_field_int", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_crc_field_int32, {"CRC field Integer", "bpv7.crc_field_int", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_crc_actual_int16, {"CRC Computed", "bpv7.crc_actual_int", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_crc_actual_int32, {"CRC Computed", "bpv7.crc_actual_int", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

    {&hf_time_dtntime, {"DTN Time", "bpv7.time.dtntime", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
    {&hf_time_utctime, {"UTC Time", "bpv7.time.utctime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL}},

    {&hf_create_ts_time, {"Time", "bpv7.create_ts.time", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_create_ts_seqno, {"Sequence Number", "bpv7.create_ts.seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_eid_scheme, {"Scheme Code", "bpv7.eid.scheme", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(eid_schemes), 0x0, NULL, HFILL}},
    {&hf_eid_dtn_ssp_code, {"DTN SSP", "bpv7.eid.dtn_ssp_code", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_eid_dtn_ssp_text, {"DTN SSP", "bpv7.eid.dtn_ssp_text", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_eid_ipn_node, {"IPN Node Number", "bpv7.eid.ipn_node", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_eid_ipn_service, {"IPN Service Number", "bpv7.eid.ipn_service", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_eid_as_uri, {"Node ID as URI", "bpv7.eid.as_uri", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_primary_version, {"Version", "bpv7.primary.version", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_bundle_flags, {"Bundle Flags", "bpv7.primary.bundle_flags", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_bundle_flags_is_fragment, {"Bundle is Fragment", "bpv7.primary.bundle_flags.is_fragment", FT_UINT32, BASE_DEC, NULL, BP_BUNDLE_IS_FRAGMENT, NULL, HFILL}},
    {&hf_primary_bundle_flags_payload_admin, {"Payload is Administrative", "bpv7.primary.bundle_flags.payload_admin", FT_UINT32, BASE_DEC, NULL, BP_BUNDLE_PAYLOAD_ADMIN, NULL, HFILL}},
    {&hf_primary_bundle_flags_no_fragment, {"Bundle must not be Fragmented", "bpv7.primary.bundle_flags.no_fragment", FT_UINT32, BASE_DEC, NULL, BP_BUNDLE_NO_FRAGMENT, NULL, HFILL}},
    {&hf_primary_bundle_flags_user_app_ack, {"Acknowledgement by Application required", "bpv7.primary.bundle_flags.user_app_ack", FT_UINT32, BASE_DEC, NULL, BP_BUNDLE_USER_APP_ACK, NULL, HFILL}},
    {&hf_primary_bundle_flags_req_status_time, {"Status time requested in reports", "bpv7.primary.bundle_flags.req_status_time", FT_UINT32, BASE_DEC, NULL, BP_BUNDLE_REQ_STATUS_TIME, NULL, HFILL}},
    {&hf_primary_bundle_flags_reception_report, {"Request reporting of bundle reception", "bpv7.primary.bundle_flags.reception_report", FT_UINT32, BASE_DEC, NULL, BP_BUNDLE_REQ_RECEPTION_REPORT, NULL, HFILL}},
    {&hf_primary_bundle_flags_forwarding_report, {"Request reporting of bundle forwarding", "bpv7.primary.bundle_flags.forwarding_report", FT_UINT32, BASE_DEC, NULL, BP_BUNDLE_REQ_FORWARDING_REPORT, NULL, HFILL}},
    {&hf_primary_bundle_flags_delivery_report, {"Request reporting of bundle delivery", "bpv7.primary.bundle_flags.delivery_report", FT_UINT32, BASE_DEC, NULL, BP_BUNDLE_REQ_DELIVERY_REPORT, NULL, HFILL}},
    {&hf_primary_bundle_flags_deletion_report, {"Request reporting of bundle deletion", "bpv7.primary.bundle_flags.deleteion_report", FT_UINT32, BASE_DEC, NULL, BP_BUNDLE_REQ_DELETION_REPORT, NULL, HFILL}},
    {&hf_primary_crc_type, {"CRC Type", "bpv7.primary.crc_type", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(crc_vals), 0x0, NULL, HFILL}},
    {&hf_primary_dst_eid, {"Destination Endpoint ID", "bpv7.primary.dst_eid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_src_nodeid, {"Source Node ID", "bpv7.primary.src_nodeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_report_nodeid, {"Report-to Node ID", "bpv7.primary.report_nodeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_create_ts, {"Creation Timestamp", "bpv7.primary.create_ts", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_lifetime, {"Lifetime", "bpv7.primary.lifetime", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_microseconds, 0x0, NULL, HFILL}},
    {&hf_primary_lifetime_exp, {"Lifetime Expanded", "bpv7.primary.lifetime_exp", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_expire_ts, {"Expire Time", "bpv7.primary.expire_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_frag_offset, {"Fragment Offset", "bpv7.primary.frag_offset", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_primary_total_length, {"Total Application Data Unit Length", "bpv7.primary.total_len", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_primary_crc_field, {"CRC Field", "bpv7.primary.crc_field", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_bundle_ident, {"Bundle Identity", "bpv7.bundle.identity", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_canonical_type_code, {"Type Code", "bpv7.canonical.type_code", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(blocktype_vals), 0x0, NULL, HFILL}},
    {&hf_canonical_block_num, {"Block Number", "bpv7.canonical.block_num", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_block_flags, {"Block Flags", "bpv7.canonical.block_flags", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_block_flags_replicate_in_fragment, {"Replicate block in fragment", "bpv7.canonical.block_flags.replicate_in_fragment", FT_UINT8, BASE_DEC, NULL, BP_BLOCK_REPLICATE_IN_FRAGMENT, NULL, HFILL}},
    {&hf_canonical_block_flags_status_no_process, {"Status bundle if not processed", "bpv7.canonical.block_flags.status_if_no_process", FT_UINT8, BASE_DEC, NULL, BP_BLOCK_STATUS_IF_NO_PROCESS, NULL, HFILL}},
    {&hf_canonical_block_flags_delete_no_process, {"Delete bundle if not processed", "bpv7.canonical.block_flags.delete_if_no_process", FT_UINT8, BASE_DEC, NULL, BP_BLOCK_DELETE_IF_NO_PROCESS, NULL, HFILL}},
    {&hf_canonical_block_flags_remove_no_process, {"Discard block if not processed", "bpv7.canonical.block_flags.discard_if_no_process", FT_UINT8, BASE_DEC, NULL, BP_BLOCK_REMOVE_IF_NO_PROCESS, NULL, HFILL}},
    {&hf_canonical_crc_type, {"CRC Type", "bpv7.canonical.crc_type", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(crc_vals), 0x0, NULL, HFILL}},
    {&hf_canonical_data, {"Type-Specific Data", "bpv7.canonical.data", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_canonical_crc_field, {"CRC Field", "bpv7.canonical.crc_field", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_previous_node_nodeid, {"Previous Node ID", "bpv7.previous_node.nodeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_bundle_age_time, {"Bundle Age", "bpv7.bundle_age.time", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_microseconds, 0x0, NULL, HFILL}},

    {&hf_hop_count_limit, {"Hop Limit", "bpv7.hop_count.limit", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_hop_count_current, {"Hop Count", "bpv7.hop_count.current", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},

    {&hf_admin_record, {"BPv7 Administrative Record", "bpv7.admin_rec", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_admin_record_type, {"Record Type Code", "bpv7.admin_rec.type_code", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(admin_type_vals), 0x0, NULL, HFILL}},

    {&hf_status_rep, {"Status Report", "bpv7.status_rep", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_status_info, {"Status Information", "bpv7.status_rep.status_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_assert_val, {"Status Value", "bpv7.status_assert.val", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_assert_time, {"Received at", "bpv7.status_assert.time", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_received, {"Reporting node received bundle", "bpv7.status_rep.received", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_forwarded, {"Reporting node forwarded bundle", "bpv7.status_rep.forwarded", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_delivered, {"Reporting node delivered bundle", "bpv7.status_rep.delivered", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_deleted, {"Reporting node deleted bundle", "bpv7.status_rep.deleted", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_reason_code, {"Reason Code", "bpv7.status_rep.reason_code", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(status_report_reason_vals), 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_src_nodeid, {"Subject Source Node ID", "bpv7.status_rep.subj_src_nodeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_ts, {"Subject Creation Timestamp", "bpv7.status_rep.subj_ts", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_frag_offset, {"Subject Fragment Offset", "bpv7.status_rep.subj_frag_offset", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_payload_len, {"Subject Payload Length", "bpv7.status_rep.subj_payload_len", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_ident, {"Subject Identity", "bpv7.status_rep.identity", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_ref, {"Subject Bundle", "bpv7.status_rep.subj_ref", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},
};

static const int *bundle_flags[] = {
    &hf_primary_bundle_flags_deletion_report,
    &hf_primary_bundle_flags_delivery_report,
    &hf_primary_bundle_flags_forwarding_report,
    &hf_primary_bundle_flags_reception_report,
    &hf_primary_bundle_flags_req_status_time,
    &hf_primary_bundle_flags_user_app_ack,
    &hf_primary_bundle_flags_no_fragment,
    &hf_primary_bundle_flags_payload_admin,
    &hf_primary_bundle_flags_is_fragment,
    NULL
};

static const int *block_flags[] = {
    &hf_canonical_block_flags_remove_no_process,
    &hf_canonical_block_flags_delete_no_process,
    &hf_canonical_block_flags_status_no_process,
    &hf_canonical_block_flags_replicate_in_fragment,
    NULL
};

static int ett_bundle = -1;
static int ett_bundle_flags = -1;
static int ett_block = -1;
static int ett_eid = -1;
static int ett_time = -1;
static int ett_create_ts = -1;
static int ett_block_flags = -1;
static int ett_canonical_data = -1;
static int ett_payload = -1;
static int ett_admin = -1;
static int ett_status_rep = -1;
static int ett_status_info = -1;
static int ett_status_assert = -1;
/// Tree structures
static int *ett[] = {
    &ett_bundle,
    &ett_bundle_flags,
    &ett_block,
    &ett_eid,
    &ett_time,
    &ett_create_ts,
    &ett_block_flags,
    &ett_canonical_data,
    &ett_payload,
    &ett_admin,
    &ett_status_rep,
    &ett_status_info,
    &ett_status_assert,
};

static expert_field ei_invalid_bp_version = EI_INIT;
static expert_field ei_eid_scheme_unknown = EI_INIT;
static expert_field ei_block_type_unknown = EI_INIT;
static expert_field ei_block_type_dupe = EI_INIT;
static expert_field ei_block_partial_decode = EI_INIT;
static expert_field ei_crc_type_unknown = EI_INIT;
static expert_field ei_block_failed_crc = EI_INIT;
static expert_field ei_block_num_dupe = EI_INIT;
static expert_field ei_block_payload_index = EI_INIT;
static expert_field ei_block_payload_num = EI_INIT;
static expert_field ei_admin_type_unknown = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_invalid_bp_version, {"bpv7.invalid_bp_version", PI_MALFORMED, PI_ERROR, "Invalid BP version", EXPFILL}},
    {&ei_eid_scheme_unknown, {"bpv7.eid_scheme_unknown", PI_UNDECODED, PI_WARN, "Unknown Node ID scheme code", EXPFILL}},
    {&ei_block_type_unknown, {"bpv7.block_type_unknown", PI_UNDECODED, PI_ERROR, "Unknown block type code", EXPFILL}},
    {&ei_block_type_dupe, {"bpv7.block_type_dupe", PI_PROTOCOL, PI_WARN, "Too many blocks of this type", EXPFILL}},
    {&ei_block_partial_decode, {"bpv7.block_partial_decode", PI_UNDECODED, PI_WARN, "Block data not fully dissected", EXPFILL}},
    {&ei_crc_type_unknown, {"bpv7.ei_crc_type_unknown", PI_UNDECODED, PI_ERROR, "Unknown CRC Type code", EXPFILL}},
    {&ei_block_failed_crc, {"bpv7.block_failed_crc", PI_CHECKSUM, PI_WARN, "Block failed CRC", EXPFILL}},
    {&ei_block_num_dupe, {"bpv7.block_num_dupe", PI_PROTOCOL, PI_WARN, "Duplicate block number", EXPFILL}},
    {&ei_block_payload_index, {"bpv7.block_payload_index", PI_PROTOCOL, PI_WARN, "Payload must be the last block", EXPFILL}},
    {&ei_block_payload_num, {"bpv7.block_payload_num", PI_PROTOCOL, PI_WARN, "Invalid payload block number", EXPFILL}},
    {&ei_admin_type_unknown, {"bpv7.admin_type_unknown", PI_UNDECODED, PI_ERROR, "Unknown administrative type code", EXPFILL}},
};

/** Delete an arbitrary object allocated under this file scope.
 *
 * @param obj The object to delete.
 */
static void file_scope_delete(gpointer ptr) {
    wmem_free(wmem_file_scope(), ptr);
}

bp_creation_ts_t * bp_creation_ts_new() {
    bp_creation_ts_t *obj = wmem_new0(wmem_file_scope(), bp_creation_ts_t);
    return obj;
}

void bp_creation_ts_delete(gpointer ptr) {
    // no sub-deletions
    file_scope_delete(ptr);
}

gint bp_creation_ts_compare(gconstpointer a, gconstpointer b, gpointer user_data _U_) {
    const bp_creation_ts_t *ats = a;
    const bp_creation_ts_t *bts = b;
    if (ats->time.dtntime < bts->time.dtntime) {
        return -1;
    }
    else if (ats->time.dtntime > bts->time.dtntime) {
        return 1;
    }

    if (ats->seqno < bts->seqno) {
        return -1;
    }
    else if (ats->seqno > bts->seqno) {
        return 1;
    }

    return 0;
}

bp_eid_t * bp_eid_new() {
    bp_eid_t *obj = wmem_new0(wmem_file_scope(), bp_eid_t);
    return obj;
}

void bp_eid_delete(gpointer ptr) {
    bp_eid_t *obj = (bp_eid_t *)ptr;
    file_scope_delete((char *)(obj->uri));
    file_scope_delete(ptr);
}

gboolean bp_eid_equal(gconstpointer a, gconstpointer b) {
    const bp_eid_t *aobj = a;
    const bp_eid_t *bobj = b;
    return aobj->uri && bobj->uri && g_str_equal(aobj->uri, bobj->uri);
}

bp_block_primary_t * bp_block_primary_new() {
    bp_block_primary_t *obj = wmem_new0(wmem_file_scope(), bp_block_primary_t);
    obj->dst_eid = bp_eid_new();
    obj->src_nodeid = bp_eid_new();
    obj->rep_nodeid = bp_eid_new();
    obj->frag_offset = NULL;
    obj->total_len = NULL;
    return obj;
}

void bp_block_primary_delete(gpointer ptr) {
    bp_block_primary_t *obj = (bp_block_primary_t *) ptr;
    bp_eid_delete(obj->dst_eid);
    bp_eid_delete(obj->src_nodeid);
    bp_eid_delete(obj->rep_nodeid);
    file_scope_delete(obj->frag_offset);
    file_scope_delete(obj->total_len);
    file_scope_delete(ptr);
}

bp_block_canonical_t * bp_block_canonical_new(guint64 index) {
    bp_block_canonical_t *obj = wmem_new0(wmem_file_scope(), bp_block_canonical_t);
    obj->index = index;
    return obj;
}

void bp_block_canonical_delete(gpointer ptr) {
    // no sub-deletions
    file_scope_delete(ptr);
}

gint bp_block_compare_index(gconstpointer a, gconstpointer b, gpointer user_data _U_) {
    const bp_block_canonical_t *ablock = a;
    const bp_block_canonical_t *bblock = b;
    if (ablock->index < bblock->index) {
        return -1;
    }
    else if (ablock->index > bblock->index) {
        return 1;
    }
    else {
        return 0;
    }
}

gint bp_block_compare_block_number(gconstpointer a, gconstpointer b, gpointer user_data _U_) {
    const bp_block_canonical_t *ablock = a;
    const bp_block_canonical_t *bblock = b;
    if (!(ablock->block_number)) {
        return -1;
    }
    if (!(bblock->block_number)) {
        return 1;
    }
    if (*(ablock->block_number) < *(bblock->block_number)) {
        return -1;
    }
    if (*(ablock->block_number) > *(bblock->block_number)) {
        return 1;
    }
    else {
        return 0;
    }
}

static guint64 * guint64_new(const guint64 val) {
    guint64 *obj = wmem_new(wmem_file_scope(), guint64);
    *obj = val;
    return obj;
}

#define guint64_delete file_scope_delete

static void gptrarray_delete(gpointer ptr) {
    GPtrArray *obj = ptr;
    g_ptr_array_free(obj, FALSE);
}

bp_bundle_t * bp_bundle_new() {
    bp_bundle_t *obj = wmem_new(wmem_file_scope(), bp_bundle_t);
    obj->primary = bp_block_primary_new();
    obj->blocks = g_sequence_new(bp_block_canonical_delete);
    obj->block_types = g_hash_table_new_full(g_int64_hash, g_int64_equal, guint64_delete, gptrarray_delete);
    return obj;
}

void bp_bundle_delete(gpointer ptr) {
    bp_bundle_t *obj = (bp_bundle_t *)ptr;
    bp_block_primary_delete(obj->primary);
    g_sequence_free(obj->blocks);
    g_hash_table_destroy(obj->block_types);
    file_scope_delete(ptr);
}

bp_bundle_ident_t * bp_bundle_ident_new(bp_eid_t *src, bp_creation_ts_t *ts, guint64 *off, guint64 *len) {
    bp_bundle_ident_t *ident = wmem_new(wmem_file_scope(), bp_bundle_ident_t);
    ident->src = src;
    ident->ts = ts;
    ident->frag_offset = off;
    ident->total_len = len;
    return ident;
}

void bp_bundle_ident_delete(gpointer ptr) {
    file_scope_delete(ptr);
}

/** Either both values are defined and equal or both are null.
 */
static gboolean optional_uint64_equal(const guint64 *a, const guint64 *b) {
    if (a && b) {
        return (*a == *b);
    }
    else {
        return (a == NULL) && (b == NULL);
    }
}

gboolean bp_bundle_ident_equal(gconstpointer a, gconstpointer b) {
    const bp_bundle_ident_t *aobj = a;
    const bp_bundle_ident_t *bobj = b;
    return (
        bp_eid_equal(aobj->src, bobj->src)
        && (aobj->ts->time.dtntime == bobj->ts->time.dtntime)
        && (aobj->ts->seqno == bobj->ts->seqno)
        && optional_uint64_equal(aobj->frag_offset, bobj->frag_offset)
        && optional_uint64_equal(aobj->total_len, bobj->total_len)
    );
}

guint bp_bundle_ident_hash(gconstpointer key) {
    const bp_bundle_ident_t *obj = key;
    return (
        g_str_hash(obj->src->uri ? obj->src->uri : "")
        ^ g_int64_hash(&(obj->ts->time.dtntime))
        ^ g_int64_hash(&(obj->ts->seqno))
    );
}

/** Convert DTN time to absolute time.
 * DTN Time is defined in Section 4.1.6.
 *
 * @param dtntime Number of milliseconds from an epoch.
 * @return The associated absolute time.
 */
static nstime_t dtn_to_utctime(const gint64 dtntime) {
    nstime_t utctime;
    utctime.secs = 946684800 + dtntime / 1000;
    utctime.nsecs = 1000000 * (dtntime % 1000);
    return utctime;
}

proto_item * proto_tree_add_cbor_eid(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, gint *offset, bp_eid_t *eid) {
    proto_item *item_eid = proto_tree_add_item(tree, hfindex, tvb, *offset, 0, ENC_NA);
    proto_tree *tree_eid = proto_item_add_subtree(item_eid, ett_eid);
    const gint eid_start = *offset;

    bp_cbor_chunk_t *chunk = cbor_require_array_with_size(tvb, pinfo, item_eid, offset, 2, 2);
    if (!chunk) {
        proto_item_set_len(item_eid, *offset - eid_start);
        return item_eid;
    }
    bp_cbor_chunk_delete(chunk);

    chunk = bp_scan_cbor_chunk(tvb, *offset);
    const guint64 *scheme = cbor_require_uint64(chunk);
    proto_item *item_scheme = proto_tree_add_cbor_uint64(tree_eid, hf_eid_scheme, pinfo, tvb, chunk, scheme);
    *offset += chunk->data_length;
    bp_cbor_chunk_delete(chunk);
    if (!scheme) {
        cbor_skip_next_item(tvb, offset);
        return item_eid;
    }

    wmem_strbuf_t *uribuf = wmem_strbuf_new(wmem_file_scope(), NULL);
    switch (*scheme) {
        case EID_SCHEME_DTN: {
            chunk = bp_scan_cbor_chunk(tvb, *offset);
            switch (chunk->type_major) {
                case CBOR_TYPE_UINT: {
                    const guint64 *ssp_code = cbor_require_uint64(chunk);
                    proto_item *item = proto_tree_add_cbor_uint64(tree_eid, hf_eid_dtn_ssp_code, pinfo, tvb, chunk, ssp_code);
                    *offset += chunk->data_length;

                    switch (*ssp_code) {
                        case 0: {
                            wmem_strbuf_append(uribuf, "dtn:none");
                            break;
                        }
                        default: {
                            expert_add_info(pinfo, item, &ei_cbor_wrong_type);
                            break;
                        }
                    }
                    break;
                }
                case CBOR_TYPE_STRING: {
                    tvbuff_t *ssp = cbor_require_string(tvb, chunk);
                    proto_tree_add_cbor_string(tree_eid, hf_eid_dtn_ssp_text, pinfo, tvb, chunk);
                    *offset += chunk->data_length;

                    char *value = (char *) tvb_get_string_enc(wmem_packet_scope(), ssp, 0, tvb_captured_length(ssp), ENC_UTF_8);
                    wmem_strbuf_append_printf(uribuf, "dtn:%s", value);
                    wmem_free(wmem_packet_scope(), value);

                    break;
                }
                default: {
                    proto_item *item = proto_tree_add_string(tree_eid, hf_eid_dtn_ssp_text, tvb, chunk->start, chunk->head_length + chunk->head_value, "");
                    expert_add_info(pinfo, item, &ei_cbor_wrong_type);
                    break;
                }
            }

            bp_cbor_chunk_delete(chunk);
            break;
        }
        case EID_SCHEME_IPN: {
            chunk = cbor_require_array_with_size(tvb, pinfo, item_eid, offset, 2, 2);
            if (!chunk) {
                proto_item_set_len(item_eid, *offset - eid_start);
                bp_cbor_chunk_delete(chunk);
            }
            else {
                bp_cbor_chunk_delete(chunk);

                chunk = bp_scan_cbor_chunk(tvb, *offset);
                const guint64 *node = cbor_require_uint64(chunk);
                proto_tree_add_cbor_uint64(tree_eid, hf_eid_ipn_node, pinfo, tvb, chunk, node);
                *offset += chunk->data_length;
                bp_cbor_chunk_delete(chunk);

                chunk = bp_scan_cbor_chunk(tvb, *offset);
                const guint64 *service = cbor_require_uint64(chunk);
                proto_tree_add_cbor_uint64(tree_eid, hf_eid_ipn_service, pinfo, tvb, chunk, service);
                *offset += chunk->data_length;
                bp_cbor_chunk_delete(chunk);

                wmem_strbuf_append_printf(uribuf, "ipn:%"PRIu64".%"PRIu64, node ? *node : 0, service ? *service : 0);
            }
            break;
        }
        default:
            cbor_skip_next_item(tvb, offset);
            expert_add_info(pinfo, item_scheme, &ei_eid_scheme_unknown);
            break;
    }

    char * uri = NULL;
    if (wmem_strbuf_get_len(uribuf) > 0) {
        uri = wmem_strbuf_finalize(uribuf);

        proto_item *item_uri = proto_tree_add_string(tree_eid, hf_eid_as_uri, tvb, eid_start, *offset - eid_start, uri);
        PROTO_ITEM_SET_GENERATED(item_uri);

        proto_item_append_text(item_eid, ": %s", uri);
    }
    else {
        file_scope_delete(uribuf);
    }

    if (eid) {
        eid->scheme = (scheme ? *scheme : 0);
        eid->uri = uri;
    }
    else {
        file_scope_delete(uri);
    }

    proto_item_set_len(item_eid, *offset - eid_start);
    return item_eid;
}

static void proto_tree_add_dtn_time(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, gint *offset, bp_dtn_time_t *out) {
    proto_item *item_time = proto_tree_add_item(tree, hfindex, tvb, *offset, 0, ENC_NA);
    proto_tree *tree_time = proto_item_add_subtree(item_time, ett_time);
    const gint offset_start = *offset;

    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, *offset);
    if (chunk) {
        const guint64 *dtntime = cbor_require_uint64(chunk);
        proto_tree_add_cbor_uint64(tree_time, hf_time_dtntime, pinfo, tvb, chunk, dtntime);
        *offset += chunk->data_length;

        if (dtntime) {
            if (out) {
                out->dtntime = *dtntime;
            }

            if (*dtntime > 0) {
                const nstime_t utctime = dtn_to_utctime(*dtntime);
                proto_item *item_utctime = proto_tree_add_time(tree_time, hf_time_utctime, tvb, chunk->start, chunk->data_length, &utctime);
                PROTO_ITEM_SET_GENERATED(item_utctime);

                gchar *time_text = abs_time_to_str(wmem_file_scope(), &utctime, ABSOLUTE_TIME_UTC, TRUE);
                proto_item_append_text(item_time, ": %s", time_text);
                file_scope_delete(time_text);

                if (out) {
                    out->utctime = utctime;
                }
            }
            else {
                proto_item_append_text(item_time, ": undefined");
            }
        }
        else if (out) {
            out->dtntime = 0;
            nstime_set_zero(&(out->utctime));
        }
    }
    bp_cbor_chunk_delete(chunk);
    proto_item_set_len(item_time, *offset - offset_start);
}

/** Extract a timestamp.
 *
 * @param tree The tree to write items under.
 * @param hfindex The root item field.
 * @param pinfo Packet info to update.
 * @param tvb Buffer to read from.
 * @param[in,out] offset Starting offset within @c tvb.
 * @param[out] ts If non-null, the timestamp to write to.
 */
static void proto_tree_add_cbor_timestamp(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, gint *offset, bp_creation_ts_t *ts) {
    proto_item *item_ts = proto_tree_add_item(tree, hfindex, tvb, *offset, 0, ENC_NA);
    proto_tree *tree_ts = proto_item_add_subtree(item_ts, ett_create_ts);
    const gint offset_start = *offset;

    bp_cbor_chunk_t *chunk = cbor_require_array_with_size(tvb, pinfo, item_ts, offset, 2, 2);
    if (chunk) {
        bp_cbor_chunk_delete(chunk);

        bp_dtn_time_t time;
        proto_tree_add_dtn_time(tree_ts, hf_create_ts_time, pinfo, tvb, offset, &time);

        chunk = bp_scan_cbor_chunk(tvb, *offset);
        const guint64 *seqno = cbor_require_uint64(chunk);
        proto_tree_add_cbor_uint64(tree_ts, hf_create_ts_seqno, pinfo, tvb, chunk, seqno);
        *offset += chunk->data_length;
        bp_cbor_chunk_delete(chunk);

        if (ts) {
            ts->time = time;
            ts->seqno = (seqno ? *seqno : 0);
        }
    }
    proto_item_set_len(item_ts, *offset - offset_start);
}

/** Show read-in and actual CRC information.
 *
 * @param tvb The single-block data.
 * @param crc_type Type of CRC to compute.
 * @param crc_field The read-in field value.
 * @param item_crc_field The field to put errors on.
 */
static void show_crc_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_block, const guint64 *crc_type, tvbuff_t *crc_field, proto_item *item_crc_field) {
    // Display the data field information
    if (crc_field) {
        int hf_crc_field;
        gint hf_crc_len;
        switch (*crc_type) {
            case BP_CRC_16:
                hf_crc_field = hf_crc_field_int16;
                hf_crc_len = 2;
                break;
            case BP_CRC_32:
                hf_crc_field = hf_crc_field_int32;
                hf_crc_len = 4;
                break;
            default:
                hf_crc_field = -1;
                hf_crc_len = 0;
                break;
        }
        proto_item *item_crc_int = proto_tree_add_item(tree_block, hf_crc_field, crc_field, 0, hf_crc_len, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_GENERATED(item_crc_int);
        proto_tree_move_item(tree_block, item_crc_field, item_crc_int);
    }

    // Compare against expected result
    if (bp_compute_crc) {
        const guint block_len = tvb_captured_length(tvb);
        const int hf_crc_actual = (*crc_type == BP_CRC_16 ? hf_crc_actual_int16 : hf_crc_actual_int32);
        guint64 crc_expect;
        guint8 *crcbuf = tvb_memdup(pinfo->pool, tvb, 0, block_len);
        guint64 crc_actual;
        switch (*crc_type) {
            case BP_CRC_16:
                crc_expect = tvb_get_guint16(crc_field, 0, ENC_BIG_ENDIAN);
                memset(crcbuf + block_len - 2, 0, 2);
                crc_actual = crc16_ccitt(crcbuf, block_len);
                break;
            case BP_CRC_32:
                crc_expect = tvb_get_guint32(crc_field, 0, ENC_BIG_ENDIAN);
                memset(crcbuf + block_len - 4, 0, 4);
                crc_actual = ~crc32c_calculate_no_swap(crcbuf, block_len, CRC32C_PRELOAD);
                break;
            default:
                crc_expect = 0;
                crc_actual = 0;
                break;
        }
        wmem_free(pinfo->pool, crcbuf);

        proto_item *item_crc_actual = proto_tree_add_uint(tree_block, hf_crc_actual, tvb, 0, block_len, crc_actual);
        PROTO_ITEM_SET_GENERATED(item_crc_actual);

        if (crc_actual != crc_expect) {
            expert_add_info(pinfo, item_crc_field, &ei_block_failed_crc);
        }
    }
}

static void proto_tree_add_ident(proto_tree *tree, int hfindex, tvbuff_t *tvb, const bp_bundle_ident_t *ident) {
    wmem_strbuf_t *ident_text = wmem_strbuf_new(wmem_packet_scope(), NULL);
    wmem_strbuf_append_printf(
        ident_text,
        "Source: %s, DTN Time: %" PRIu64 ", Seq: %" PRIu64,
        ident->src->uri,
        ident->ts->time.dtntime,
        ident->ts->seqno
    );
    if (ident->frag_offset) {
        wmem_strbuf_append_printf(ident_text, ", Frag Offset: %" PRIu64, *(ident->frag_offset));
    }
    if (ident->total_len) {
        wmem_strbuf_append_printf(ident_text, ", Total Length: %" PRIu64, *(ident->total_len));
    }

    proto_item *item_subj_ident = proto_tree_add_string(tree, hfindex, tvb, 0, 0, wmem_strbuf_get_str(ident_text));
    PROTO_ITEM_SET_GENERATED(item_subj_ident);
    wmem_strbuf_finalize(ident_text);
}


static gint dissect_block_primary(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_block,
                                  gint start, bp_block_primary_t *block,
                                  bp_bundle_t *bundle _U_) {
    proto_item *item_block = proto_tree_get_parent(tree_block);
    gint field_ix = 0;
    gint offset = start;

    bp_cbor_chunk_t *chunk_head = cbor_require_array_with_size(tvb, pinfo, item_block, &offset, 8, 11);
    if (!chunk_head) {
        return offset - start;
    }
#if 0
    proto_item_append_text(item_block, ", Items: %" PRIu64, chunk_head->head_value);
#endif

    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, offset);
    const guint64 *version = cbor_require_uint64(chunk);
    proto_item *item_version = proto_tree_add_cbor_uint64(tree_block, hf_primary_version, pinfo, tvb, chunk, version);
    offset += chunk->data_length;
    field_ix++;
    bp_cbor_chunk_delete(chunk);
    if (version && (*version != 7)) {
        expert_add_info(pinfo, item_version, &ei_invalid_bp_version);
    }

    chunk = bp_scan_cbor_chunk(tvb, offset);
    const guint64 *flags = cbor_require_uint64(chunk);
    proto_tree_add_cbor_bitmask(tree_block, hf_primary_bundle_flags, ett_bundle_flags, bundle_flags, pinfo, tvb, chunk, flags);
    offset += chunk->data_length;
    field_ix++;
    bp_cbor_chunk_delete(chunk);
    block->flags = (flags ? *flags : 0);

    chunk = bp_scan_cbor_chunk(tvb, offset);
    guint64 *crc_type = cbor_require_uint64(chunk);
    proto_item *item_crc_type = proto_tree_add_cbor_uint64(tree_block, hf_primary_crc_type, pinfo, tvb, chunk, crc_type);
    offset += chunk->data_length;
    field_ix++;
    bp_cbor_chunk_delete(chunk);
    block->crc_type = (crc_type ? *crc_type : BP_CRC_NONE);
    if (crc_type) {
        proto_item_append_text(item_block, ", CRC Type: %s", val64_to_str(*crc_type, crc_vals, "%" PRIu64));
    }

    proto_tree_add_cbor_eid(tree_block, hf_primary_dst_eid, pinfo, tvb, &offset, block->dst_eid);
    field_ix++;

    proto_tree_add_cbor_eid(tree_block, hf_primary_src_nodeid, pinfo, tvb, &offset, block->src_nodeid);
    field_ix++;

    proto_tree_add_cbor_eid(tree_block, hf_primary_report_nodeid, pinfo, tvb, &offset, block->rep_nodeid);
    field_ix++;

    // Complex type
    proto_tree_add_cbor_timestamp(tree_block, hf_primary_create_ts, pinfo, tvb, &offset, &(block->ts));
    field_ix++;

    chunk = bp_scan_cbor_chunk(tvb, offset);
    const guint64 *lifetime = cbor_require_uint64(chunk);
    proto_tree_add_cbor_uint64(tree_block, hf_primary_lifetime, pinfo, tvb, chunk, lifetime);
    if (lifetime) {
        nstime_t lifetime_exp;
        lifetime_exp.secs = *lifetime / 1000000;
        lifetime_exp.nsecs = (*lifetime % 1000000) * 1000;
        proto_item *item_lifetime_exp = proto_tree_add_time(tree_block, hf_primary_lifetime_exp, tvb, chunk->start, chunk->head_length, &lifetime_exp);
        PROTO_ITEM_SET_GENERATED(item_lifetime_exp);

        if (block->ts.time.dtntime > 0) {
            nstime_t expiretime;
            nstime_sum(&expiretime, &(block->ts.time.utctime), &lifetime_exp);
            proto_item *item_expiretime = proto_tree_add_time(tree_block, hf_primary_expire_ts, tvb, 0, 0, &expiretime);
            PROTO_ITEM_SET_GENERATED(item_expiretime);
        }
    }
    offset += chunk->data_length;
    field_ix++;
    bp_cbor_chunk_delete(chunk);

    // optional items
    if (flags && (*flags & BP_BUNDLE_IS_FRAGMENT)) {
        if (!cbor_require_array_size(tvb, pinfo, item_block, chunk_head, field_ix + 1, field_ix + 3)) {
            // Skip whole array
            offset = start;
            cbor_skip_next_item(tvb, &offset);

            bp_cbor_chunk_delete(chunk_head);
            return offset - start;
        }

        chunk = bp_scan_cbor_chunk(tvb, offset);
        block->frag_offset = cbor_require_uint64(chunk);
        proto_tree_add_cbor_uint64(tree_block, hf_primary_frag_offset, pinfo, tvb, chunk, block->frag_offset);
        offset += chunk->data_length;
        field_ix++;
        bp_cbor_chunk_delete(chunk);

        chunk = bp_scan_cbor_chunk(tvb, offset);
        block->total_len = cbor_require_uint64(chunk);
        proto_tree_add_cbor_uint64(tree_block, hf_primary_total_length, pinfo, tvb, chunk, block->total_len);
        offset += chunk->data_length;
        field_ix++;
        bp_cbor_chunk_delete(chunk);
    }

    switch (block->crc_type) {
        case BP_CRC_NONE:
            break;
        case BP_CRC_16:
        case BP_CRC_32: {
            if (!cbor_require_array_size(tvb, pinfo, item_block, chunk_head, field_ix + 1, field_ix + 1)) {
                // Skip whole array
                offset = start;
                cbor_skip_next_item(tvb, &offset);

                bp_cbor_chunk_delete(chunk_head);
                return offset - start;
            }

            chunk = bp_scan_cbor_chunk(tvb, offset);
            tvbuff_t *crc_field = cbor_require_string(tvb, chunk);
            proto_item *item_crc_field = proto_tree_add_cbor_string(tree_block, hf_primary_crc_field, pinfo, tvb, chunk);
            offset += chunk->data_length;
            field_ix++;
            bp_cbor_chunk_delete(chunk);
            block->crc_field = crc_field;

            tvbuff_t *tvb_block = tvb_new_subset_length(tvb, start, offset - start);
            show_crc_info(tvb_block, pinfo, tree_block, crc_type, crc_field, item_crc_field);
            break;
        }
        default:
            expert_add_info(pinfo, item_crc_type, &ei_crc_type_unknown);
            break;
    }

    bp_cbor_chunk_delete(chunk_head);
    return offset - start;
}

static gint dissect_block_canonical(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_block,
                                    gint start, bp_block_canonical_t *block,
                                    bp_bundle_t *bundle _U_) {
    proto_item *item_block = proto_tree_get_parent(tree_block);
    gint field_ix = 0;
    gint offset = start;

    bp_cbor_chunk_t *chunk_head = cbor_require_array_with_size(tvb, pinfo, item_block, &offset, 5, 6);
    if (!chunk_head) {
        return offset - start;
    }
#if 0
    proto_item_append_text(item_block, ", Items: %" PRIu64, chunk_head->head_value);
#endif

    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, offset);
    const guint64 *type_code = cbor_require_uint64(chunk);
    proto_item *item_type = proto_tree_add_cbor_uint64(tree_block, hf_canonical_type_code, pinfo, tvb, chunk, type_code);
    offset += chunk->data_length;
    field_ix++;
    bp_cbor_chunk_delete(chunk);
    block->type_code = type_code;

    // Check duplicate of this type
    if (type_code) {
        guint64 limit = UINT64_MAX;
        for (int ix = 0; ; ++ix) {
            const blocktype_limit *row = blocktype_limits + ix;
            if (row->type_code == BP_BLOCKTYPE_INVALID) {
                break;
            }
            if (row->type_code == *type_code) {
                limit = row->limit;
                break;
            }
        }

        guint64 count = 1; // this block counts regardless of presence in the map
        GPtrArray *list_found = g_hash_table_lookup(bundle->block_types, type_code);
        if (list_found) {
            for (guint ix = 0; ix < list_found->len; ++ix) {
                const gpointer block_found = g_ptr_array_index(list_found, ix);
                if (block == block_found) {
                    continue;
                }
                ++count;
            }
        }

        if (count > limit) {
            // First non-identical block triggers the error
            expert_add_info(pinfo, item_type, &ei_block_type_dupe);
        }
    }

    proto_item_append_text(item_block, ": %s", val64_to_str(*type_code, blocktype_vals, "Type %" PRIu64));
    dissector_handle_t data_dissect = NULL;
    if (type_code) {
        data_dissect = dissector_get_uint_handle(block_dissectors, *type_code);
    }

    chunk = bp_scan_cbor_chunk(tvb, offset);
    const guint64 *block_num = cbor_require_uint64(chunk);
    proto_item *item_block_num = proto_tree_add_cbor_uint64(tree_block, hf_canonical_block_num, pinfo, tvb, chunk, block_num);
    offset += chunk->data_length;
    field_ix++;
    bp_cbor_chunk_delete(chunk);
    block->block_number = block_num;
    if (block_num) {
        proto_item_append_text(item_block, ", Block Num: %" PRIu64, *block_num);
    }

    chunk = bp_scan_cbor_chunk(tvb, offset);
    const guint64 *flags = cbor_require_uint64(chunk);
    proto_tree_add_cbor_bitmask(tree_block, hf_canonical_block_flags, ett_block_flags, block_flags, pinfo, tvb, chunk, flags);
    offset += chunk->data_length;
    field_ix++;
    bp_cbor_chunk_delete(chunk);
    block->flags = (flags ? *flags : 0);

    chunk = bp_scan_cbor_chunk(tvb, offset);
    guint64 *crc_type = cbor_require_uint64(chunk);
    proto_item *item_crc_type = proto_tree_add_cbor_uint64(tree_block, hf_canonical_crc_type, pinfo, tvb, chunk, crc_type);
    offset += chunk->data_length;
    field_ix++;
    bp_cbor_chunk_delete(chunk);
    block->crc_type = (crc_type ? *crc_type : BP_CRC_NONE);
    if (crc_type) {
        proto_item_append_text(item_block, ", CRC Type: %s", val64_to_str(*crc_type, crc_vals, "%" PRIu64));
    }

    chunk = bp_scan_cbor_chunk(tvb, offset);
    tvbuff_t *tvb_data = cbor_require_string(tvb, chunk);
    offset += chunk->data_length;
    field_ix++;
    bp_cbor_chunk_delete(chunk);
    block->data = tvb_data;
    const guint tvb_data_len = (tvb_data ? tvb_captured_length(tvb_data) : 0);
    //proto_item *item_data = proto_tree_add_item(tree_block, hf_canonical_data, tvb_data, 0, tvb_data_len, ENC_NA);
    proto_item *item_data = proto_tree_add_uint64(tree_block, hf_canonical_data, tvb_data, 0, tvb_data_len, tvb_data_len);
    proto_tree *tree_data = proto_item_add_subtree(item_data, ett_canonical_data);
    if (!tvb_data) {
        expert_add_info_format(pinfo, item_data, &ei_item_missing, "Data field is missing");
    }

    switch (block->crc_type) {
        case BP_CRC_NONE:
            break;
        case BP_CRC_16:
        case BP_CRC_32: {
            if (!cbor_require_array_size(tvb, pinfo, item_block, chunk_head, field_ix + 1, field_ix + 1)) {
                // Skip whole array
                offset = start;
                cbor_skip_next_item(tvb, &offset);

                bp_cbor_chunk_delete(chunk_head);
                return offset - start;
            }

            chunk = bp_scan_cbor_chunk(tvb, offset);
            tvbuff_t *crc_field = cbor_require_string(tvb, chunk);
            proto_item *item_crc_field = proto_tree_add_cbor_string(tree_block, hf_canonical_crc_field, pinfo, tvb, chunk);
            offset += chunk->data_length;
            field_ix++;
            bp_cbor_chunk_delete(chunk);
            block->crc_field = crc_field;

            tvbuff_t *tvb_block = tvb_new_subset_length(tvb, start, offset - start);
            show_crc_info(tvb_block, pinfo, tree_block, crc_type, crc_field, item_crc_field);
            break;
        }
        default:
            expert_add_info(pinfo, item_crc_type, &ei_crc_type_unknown);
            break;
    }

    if (tvb_data) {
        // sub-dissect after all is read
        if (!data_dissect) {
            expert_add_info(pinfo, item_type, &ei_block_type_unknown);
            call_data_dissector(tvb_data, pinfo, tree_block);
        }
        else {
            bp_dissector_data_t dissect_data;
            dissect_data.bundle = bundle;
            dissect_data.block = block;
            const int sublen = call_dissector_with_data(data_dissect, tvb_data, pinfo, tree_data, &dissect_data);
            if ((sublen < 0) || ((guint)sublen < tvb_data_len)) {
                expert_add_info(pinfo, item_block, &ei_block_partial_decode);
            }
        }
    }

    GSequenceIter *same_num = g_sequence_lookup(bundle->blocks, block, bp_block_compare_block_number, NULL);
    if (same_num) {
        expert_add_info(pinfo, item_block_num, &ei_block_num_dupe);
    }

    GSequenceIter *block_iter = g_sequence_lookup(bundle->blocks, block, bp_block_compare_index, NULL);
    if (!block_iter) {
        block_iter = g_sequence_insert_sorted(bundle->blocks, block, bp_block_compare_index, NULL);
    }

    // Payload block requirements
    if (block->type_code && (*(block->type_code) == BP_BLOCKTYPE_PAYLOAD)) {
        // must have index zero
        if (block->block_number && (*(block->block_number) != 1)) {
            expert_add_info(pinfo, item_block_num, &ei_block_payload_num);
        }
        // must be last block
        if (!g_sequence_iter_is_end(g_sequence_iter_next(block_iter))) {
            expert_add_info(pinfo, item_block, &ei_block_payload_index);
        }
    }

    return offset - start;
}

/// Top-level protocol dissector
static int dissect_bp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    {
        const gchar *proto_name = col_get_text(pinfo->cinfo, COL_PROTOCOL);
        if (proto_name && (strncmp(proto_name, "BPv7", 5) != 0)) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "BPv7");
        }
    }

    proto_item *item_bundle = proto_tree_add_item(tree, hf_bundle, tvb, 0, 0, ENC_NA);
    proto_tree *tree_bundle = proto_item_add_subtree(item_bundle, ett_bundle);

    bp_bundle_t *bundle = bp_bundle_new();
    bundle->frame_num = pinfo->num;

    // Read blocks directly from buffer with same addresses as #tvb
    const guint buflen = tvb_captured_length(tvb);

    // Require indefinite-length array type
    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, offset);
    proto_item *item_head = proto_tree_add_item(tree_bundle, hf_bundle_head, tvb, offset, chunk->data_length, ENC_NA);
    offset += chunk->data_length;
    if (chunk->type_major != CBOR_TYPE_ARRAY) {
        expert_add_info_format(pinfo, item_head, &ei_cbor_wrong_type, "Bundle root has type %d, should be %d", chunk->type_major, CBOR_TYPE_ARRAY);
        return buflen;
    }
    else if (chunk->type_minor != 31) {
        expert_add_info_format(pinfo, item_head, &ei_cbor_array_wrong_size, "Expected indefinite length array");
        // continue on even for definite-length array
    }
    bp_cbor_chunk_delete(chunk);

    guint64 block_ix = 0;
    bp_bundle_ident_t *ident = NULL;
    while (TRUE) {
        if (offset >= (gint)buflen) {
            proto_item *item_break = proto_tree_add_item(tree_bundle, hf_bundle_break, tvb, offset, 0, ENC_NA);
            expert_add_info_format(pinfo, item_break, &ei_cbor_array_wrong_size, "Array break missing");
            break;
        }
        chunk = bp_scan_cbor_chunk(tvb, offset);
        if (cbor_is_indefinite_break(chunk)) {
            proto_tree_add_item(tree_bundle, hf_bundle_break, tvb, offset, chunk->head_length, ENC_NA);
            offset += chunk->data_length;
            bp_cbor_chunk_delete(chunk);
            break;
        }
        bp_cbor_chunk_delete(chunk);

        // Load just the array start
        const gint block_start = offset;
        proto_item *item_block = proto_tree_add_item(tree_bundle, hf_block, tvb, block_start, 0, ENC_NA);
        proto_tree *tree_block = proto_item_add_subtree(item_block, ett_block);

        if (block_ix == 0) {
            // Primary block
            proto_item_prepend_text(item_block, "Primary ");
            bp_block_primary_t *block = bp_block_primary_new();
            offset += dissect_block_primary(tvb, pinfo, tree_block, offset, block, bundle);
            bundle->primary = block;

            if (!ident) {
                ident = bp_bundle_ident_new(
                    bundle->primary->src_nodeid,
                    &(bundle->primary->ts),
                    bundle->primary->frag_offset,
                    bundle->primary->total_len
                );
                proto_tree_add_ident(tree_bundle, hf_bundle_ident, tvb, ident);
            }
        }
        else {
            // Non-primary block
            proto_item_prepend_text(item_block, "Canonical ");
            bp_block_canonical_t *block = bp_block_canonical_new(block_ix);
            offset += dissect_block_canonical(tvb, pinfo, tree_block, offset, block, bundle);

            if (block->type_code) {
                GPtrArray *type_list = g_hash_table_lookup(bundle->block_types, block->type_code);
                if (!type_list) {
                    type_list = g_ptr_array_new();
                    g_hash_table_insert(bundle->block_types, guint64_new(*(block->type_code)), type_list);
                }

                g_ptr_array_add(type_list, block);
            }
        }

        proto_item_set_len(item_block, offset - block_start);
        block_ix++;
    }

    proto_item_append_text(item_bundle, ", Blocks: %"PRIu64, block_ix);
    if (bundle->primary) {
        const bp_block_primary_t *block = bundle->primary;
        proto_item_append_text(item_bundle, ", Src: %s", block->src_nodeid ? block->src_nodeid->uri : NULL);
        proto_item_append_text(item_bundle, ", Dst: %s", block->dst_eid ? block->dst_eid->uri : NULL);
    }

    // Keep bundle metadata around
    gpointer ident_found = g_hash_table_lookup(bp_history->bundles, ident);
    if (!ident_found) {
        g_hash_table_insert(bp_history->bundles, ident, bundle);
    }
    else {
        bp_bundle_ident_delete(ident);
        bp_bundle_delete(bundle);
    }

    proto_item_set_len(item_bundle, offset);
    return buflen;
}

static gboolean proto_tree_add_status_assertion(proto_tree *tree, int hfassert, packet_info *pinfo, tvbuff_t *tvb, gint *offset) {
    const gint assert_start = *offset;
    proto_item *item_assert = proto_tree_add_item(tree, hfassert, tvb, assert_start, 0, ENC_NA);
    proto_tree *tree_assert = proto_item_add_subtree(item_assert, ett_status_assert);

    gboolean result = FALSE;

    bp_cbor_chunk_t *head = cbor_require_array_with_size(tvb, pinfo, item_assert, offset, 1, 2);
    if (!head) {
        proto_item_set_len(item_assert, *offset - assert_start);
        return result;
    }

    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, *offset);
    gboolean *status_val = cbor_require_boolean(chunk);
    proto_tree_add_cbor_boolean(tree_assert, hf_status_assert_val, pinfo, tvb, chunk, status_val);
    *offset += chunk->data_length;
    bp_cbor_chunk_delete(chunk);
    if (status_val) {
        result = *status_val;
        file_scope_delete(status_val);
    }

    if (head->head_value > 1) {
        bp_dtn_time_t time;
        proto_tree_add_dtn_time(tree_assert, hf_status_assert_time, pinfo, tvb, offset, &time);
    }

    bp_cbor_chunk_delete(head);
    proto_item_set_len(item_assert, *offset - assert_start);

    return result;
}

static int dissect_payload_admin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bp_dissector_data_t *context) {
    proto_item *item_rec = proto_tree_add_item(tree, hf_admin_record, tvb, 0, 0, ENC_NA);
    proto_tree *tree_rec = proto_item_add_subtree(item_rec, ett_admin);
    gint offset = 0;

    bp_cbor_chunk_t *chunk = cbor_require_array_with_size(tvb, pinfo, item_rec, &offset, 2, 2);
    if (!chunk) {
        proto_item_set_len(item_rec, offset);
        return offset;
    }
    bp_cbor_chunk_delete(chunk);

    chunk = bp_scan_cbor_chunk(tvb, offset);
    const guint64 *type_code = cbor_require_uint64(chunk);
    proto_item *item_type = proto_tree_add_cbor_uint64(tree_rec, hf_admin_record_type, pinfo, tvb, chunk, type_code);
    offset += chunk->data_length;
    bp_cbor_chunk_delete(chunk);

    dissector_handle_t admin_dissect = NULL;
    if (type_code) {
        proto_item_append_text(item_rec, ": %s", val64_to_str(*type_code, admin_type_vals, "Type %" PRIu64));
        admin_dissect = dissector_get_uint_handle(admin_dissectors, *type_code);
    }
    tvbuff_t *tvb_record = tvb_new_subset_remaining(tvb, offset);
    gint sublen = 0;
    if (admin_dissect) {
        sublen = call_dissector_with_data(admin_dissect, tvb_record, pinfo, tree_rec, context);
        if ((sublen < 0) || ((guint)sublen < tvb_captured_length(tvb_record))) {
            expert_add_info(pinfo, item_type, &ei_block_partial_decode);
        }
    }
    if (sublen == 0) {
        if (dissect_media) {
            sublen = dissector_try_string(
                dissect_media,
                "application/cbor",
                tvb_record,
                pinfo,
                tree_rec,
                NULL
            );
        }
    }
    if (sublen == 0) {
        sublen = call_data_dissector(tvb_record, pinfo, tree_rec);
    }
    offset += sublen;

    proto_item_set_len(item_rec, offset);
    return offset;
}

static int dissect_status_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    bp_dissector_data_t *context = (bp_dissector_data_t *)data;
    if (!context) {
        return -1;
    }
    const gint status_start = 0;
    gint offset = 0;

    // Status Information array head
    proto_item *item_status = proto_tree_add_item(tree, hf_status_rep, tvb, status_start, 0, ENC_NA);
    proto_tree *tree_status = proto_item_add_subtree(item_status, ett_status_rep);
    gint status_field_ix = 0;

    bp_cbor_chunk_t *chunk_status = cbor_require_array_with_size(tvb, pinfo, item_status, &offset, 4, 6);
    if (!chunk_status) {
        proto_item_set_len(item_status, offset - status_start);
        return offset;
    }

    bp_cbor_chunk_t *chunk;
    gboolean status_received = FALSE;
    gboolean status_forwarded = FALSE;
    gboolean status_delivered = FALSE;
    gboolean status_deleted = FALSE;
    {
        const gint info_start = offset;
        proto_item *item_info = proto_tree_add_item(tree_status, hf_status_rep_status_info, tvb, info_start, 0, ENC_NA);
        proto_tree *tree_info = proto_item_add_subtree(item_info, ett_status_info);
        chunk = cbor_require_array_with_size(tvb, pinfo, item_info, &offset, 4, 4);
        if (!chunk) {
            proto_item_set_len(item_status, offset - status_start);
            proto_item_set_len(item_info, offset - info_start);
            return offset;
        }
        status_received = proto_tree_add_status_assertion(tree_info, hf_status_rep_received, pinfo, tvb, &offset);
        status_forwarded = proto_tree_add_status_assertion(tree_info, hf_status_rep_forwarded, pinfo, tvb, &offset);
        status_delivered = proto_tree_add_status_assertion(tree_info, hf_status_rep_delivered, pinfo, tvb, &offset);
        status_deleted = proto_tree_add_status_assertion(tree_info, hf_status_rep_deleted, pinfo, tvb, &offset);

        bp_cbor_chunk_delete(chunk);
        status_field_ix++;

        proto_item_set_len(item_info, offset - info_start);
    }

    chunk = bp_scan_cbor_chunk(tvb, offset);
    guint64 *reason_code = cbor_require_uint64(chunk);
    proto_tree_add_cbor_uint64(tree_status, hf_status_rep_reason_code, pinfo, tvb, chunk, reason_code);
    offset += chunk->data_length;
    bp_cbor_chunk_delete(chunk);
    status_field_ix++;

    bp_bundle_ident_t *subj = bp_bundle_ident_new(bp_eid_new(), bp_creation_ts_new(), NULL, NULL);

    proto_tree_add_cbor_eid(tree_status, hf_status_rep_subj_src_nodeid, pinfo, tvb, &offset, subj->src);
    status_field_ix++;

    proto_tree_add_cbor_timestamp(tree_status, hf_status_rep_subj_ts, pinfo, tvb, &offset, subj->ts);
    status_field_ix++;

    if (chunk_status->head_value > status_field_ix) {
        chunk = bp_scan_cbor_chunk(tvb, offset);
        subj->frag_offset = cbor_require_uint64(chunk);
        proto_tree_add_cbor_uint64(tree_status, hf_status_rep_subj_frag_offset, pinfo, tvb, chunk, subj->frag_offset);
        offset += chunk->data_length;
        bp_cbor_chunk_delete(chunk);
        status_field_ix++;
    }

    if (chunk_status->head_value > status_field_ix) {
        chunk = bp_scan_cbor_chunk(tvb, offset);
        subj->total_len = cbor_require_uint64(chunk);
        proto_tree_add_cbor_uint64(tree_status, hf_status_rep_subj_payload_len, pinfo, tvb, chunk, subj->total_len);
        offset += chunk->data_length;
        bp_cbor_chunk_delete(chunk);
        status_field_ix++;
    }

    proto_tree_add_ident(tree_status, hf_status_rep_subj_ident, tvb, subj);

    const bp_bundle_t *subj_found = g_hash_table_lookup(bp_history->bundles, subj);
    if (subj_found) {
        proto_item *item_subj_ref = proto_tree_add_uint(tree_status, hf_status_rep_subj_ref, tvb, 0, 0, subj_found->frame_num);
        PROTO_ITEM_SET_GENERATED(item_subj_ref);
    }
    bp_bundle_ident_delete(subj);

    proto_item *item_admin = proto_tree_get_parent(tree);
    {
        wmem_strbuf_t *status_text = wmem_strbuf_new(wmem_packet_scope(), NULL);
        gboolean sep = FALSE;
        if (status_received) {
            if (sep) {
                wmem_strbuf_append(status_text, "|");
            }
            wmem_strbuf_append(status_text, "RECEIVED");
            sep = TRUE;
        }
        if (status_forwarded) {
            if (sep) {
                wmem_strbuf_append(status_text, "|");
            }
            wmem_strbuf_append(status_text, "FORWARDED");
            sep = TRUE;
        }
        if (status_delivered) {
            if (sep) {
                wmem_strbuf_append(status_text, "|");
            }
            wmem_strbuf_append(status_text, "DELIVERED");
            sep = TRUE;
        }
        if (status_deleted) {
            if (sep) {
                wmem_strbuf_append(status_text, "|");
            }
            wmem_strbuf_append(status_text, "DELETED");
            sep = TRUE;
        }
        proto_item_append_text(item_admin, ", Status: %s", wmem_strbuf_get_str(status_text));
        wmem_strbuf_finalize(status_text);
    }
    if (reason_code) {
        proto_item_append_text(item_admin, ", Reason: %s", val64_to_str(*reason_code, status_report_reason_vals, "%" PRIu64));
    }

    proto_item_set_len(item_status, offset - status_start);
    bp_cbor_chunk_delete(chunk_status);
    return offset;
}

/** Dissector for Bundle Payload block.
 */
static int dissect_block_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    bp_dissector_data_t *context = (bp_dissector_data_t *)data;
    if (!context) {
        return -1;
    }

    // Parent bundle tree
    proto_tree *tree_block = proto_tree_get_parent_tree(tree);
    proto_tree *tree_bundle = proto_tree_get_parent_tree(tree_block);
    proto_tree *item_bundle = proto_tree_get_parent(tree_bundle);
    // Back up to top-level
    proto_item *tree_top = proto_tree_get_parent_tree(tree_bundle);

    // Visible in new source
    tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb, 0);
    add_new_data_source(pinfo, tvb_payload, "Bundle Payload");
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Bundle");

    if (context->bundle->primary->flags & BP_BUNDLE_PAYLOAD_ADMIN) {
        proto_item_append_text(item_bundle, ", ADMIN");
    }
    if (context->bundle->primary->flags & BP_BUNDLE_IS_FRAGMENT) {
        proto_item_append_text(item_bundle, ", FRAGMENT");
    }
    proto_item_append_text(item_bundle, ", Payload-Size: %d", tvb_captured_length(tvb_payload));

    // Payload is known to be administrative, independent of Node ID
    if (context->bundle->primary->flags & BP_BUNDLE_PAYLOAD_ADMIN) {
        col_append_str(pinfo->cinfo, COL_INFO, " [Admin]");
        return dissect_payload_admin(tvb_payload, pinfo, tree_top, context);
    }

    const char *eid_uri = context->bundle->primary->dst_eid->uri;
    dissector_handle_t payload_dissect = NULL;
    if (eid_uri) {
        payload_dissect = dissector_get_string_handle(payload_dissectors, eid_uri);
    }
    if (!payload_dissect) {
        return call_data_dissector(tvb_payload, pinfo, tree_top);
    }
    else {
        return call_dissector_with_data(payload_dissect, tvb_payload, pinfo, tree_top, &data);
    }
}

/** Dissector for Previous Node block.
 */
static int dissect_block_prev_node(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    proto_tree_add_cbor_eid(tree, hf_previous_node_nodeid, pinfo, tvb, &offset, NULL);

    return offset;
}

/** Dissector for Bundle Age block.
 */
static int dissect_block_bundle_age(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, offset);
    const guint64 *age = cbor_require_uint64(chunk);
    proto_tree_add_cbor_uint64(tree, hf_bundle_age_time, pinfo, tvb, chunk, age);
    offset += chunk->data_length;
    bp_cbor_chunk_delete(chunk);

    return offset;
}

/** Dissector for Hop Count block.
 */
static int dissect_block_hop_count(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item *item = proto_tree_get_parent(tree);
    gint offset = 0;

    bp_cbor_chunk_t *chunk = cbor_require_array_with_size(tvb, pinfo, item, &offset, 2, 2);
    if (!chunk) {
        return offset;
    }
    bp_cbor_chunk_delete(chunk);

    chunk = bp_scan_cbor_chunk(tvb, offset);
    const guint64 *limit = cbor_require_uint64(chunk);
    proto_tree_add_cbor_uint64(tree, hf_hop_count_limit, pinfo, tvb, chunk, limit);
    offset += chunk->data_length;
    bp_cbor_chunk_delete(chunk);

    chunk = bp_scan_cbor_chunk(tvb, offset);
    const guint64 *current = cbor_require_uint64(chunk);
    proto_tree_add_cbor_uint64(tree, hf_hop_count_current, pinfo, tvb, chunk, current);
    offset += chunk->data_length;
    bp_cbor_chunk_delete(chunk);

    return offset;
}

/// Clear state when new file scope is entered
static void history_init(void) {
    bp_history = wmem_new0(wmem_file_scope(), bp_history_t);
    bp_history->bundles = g_hash_table_new_full(bp_bundle_ident_hash, bp_bundle_ident_equal, bp_bundle_ident_delete, bp_bundle_delete);
}

static void history_cleanup(void) {
    g_hash_table_destroy(bp_history->bundles);
    file_scope_delete(bp_history);
}

/// Re-initialize after a configuration change
static void reinit_bp(void) {
}

/// Overall registration of the protocol
static void proto_register_bp(void) {
    proto_bp = proto_register_protocol(
        "DTN Bundle Protocol Version 7", /* name */
        "BPv7", /* short name */
        "bpv7" /* abbrev */
    );
    register_init_routine(&history_init);
    register_cleanup_routine(&history_cleanup);

    proto_register_field_array(proto_bp, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_bp);
    bp_cbor_init(expert);
    expert_register_field_array(expert, expertitems, array_length(expertitems));

    register_dissector("bpv7", dissect_bp, proto_bp);
    block_dissectors = register_dissector_table("bpv7.block_type", "BPv7 Block", proto_bp, FT_UINT32, BASE_HEX);
    payload_dissectors = register_dissector_table("bpv7.payload_eid_demux", "BPv7 Payload (by Endpoint ID demux)", proto_bp, FT_STRING, BASE_NONE);
    admin_dissectors = register_dissector_table("bpv7.admin_record_type", "BPv7 Administrative Record", proto_bp, FT_UINT32, BASE_HEX);

    module_t *module_bp = prefs_register_protocol(proto_bp, reinit_bp);
    prefs_register_bool_preference(
        module_bp,
        "compute_crc",
        "Compute and compare CRCs",
        "If enabled, the blocks will have CRC checks performed.",
        &bp_compute_crc
    );
}

static void proto_reg_handoff_bp(void) {
    dissect_media = find_dissector_table("media_type");

    /* Packaged extensions */
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_block_payload, proto_bp);
        dissector_add_uint("bpv7.block_type", BP_BLOCKTYPE_PAYLOAD, hdl);
    }
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_block_prev_node, proto_bp);
        dissector_add_uint("bpv7.block_type", BP_BLOCKTYPE_PREV_NODE, hdl);
    }
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_block_bundle_age, proto_bp);
        dissector_add_uint("bpv7.block_type", BP_BLOCKTYPE_BUNDLE_AGE, hdl);
    }
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_block_hop_count, proto_bp);
        dissector_add_uint("bpv7.block_type", BP_BLOCKTYPE_HOP_COUNT, hdl);
    }
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_status_report, proto_bp);
        dissector_add_uint("bpv7.admin_record_type", BP_ADMINTYPE_BUNDLE_STATUS, hdl);
    }

    reinit_bp();
}

#define PP_STRINGIZE_I(text) #text

/// Interface for wireshark plugin
WS_DLL_PUBLIC_DEF const char plugin_version[] = "0.0";
/// Interface for wireshark plugin
WS_DLL_PUBLIC_DEF const char plugin_release[] = PP_STRINGIZE_I(WIRESHARK_VERSION_MAJOR) "." PP_STRINGIZE_I(WIRESHARK_VERSION_MINOR);
/// Interface for wireshark plugin
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
/// Interface for wireshark plugin
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;
/// Interface for wireshark plugin
WS_DLL_PUBLIC_DEF void plugin_register(void) {
    static proto_plugin plugin_bp;
    plugin_bp.register_protoinfo = proto_register_bp;
    plugin_bp.register_handoff = proto_reg_handoff_bp;
    proto_register_plugin(&plugin_bp);
}
