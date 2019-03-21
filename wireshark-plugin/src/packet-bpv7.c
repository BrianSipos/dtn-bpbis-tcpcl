#include "packet-bpv7.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <cbor.h>
#include <stdio.h>
#include <inttypes.h>

/// Protocol preferences and defaults
static gboolean bp_compute_crc = FALSE;

/// Protocol handles
static int proto_bp = -1;

/// Dissector handles
static dissector_handle_t handle_bp;

/// Extension sub-dissectors
static dissector_table_t block_dissector;
static dissector_table_t payload_dissector;

/*
static const value_string sess_term_reason_vals[]={
    {0x00, "Unknown"},
    {0x01, "Idle timeout"},
    {0x02, "Version mismatch"},
    {0x03, "Busy"},
    {0x04, "Contact Failure"},
    {0x05, "Resource Exhaustion"},
    {0, NULL},
};
*/

static int hf_bundle = -1;
static int hf_block = -1;

static int hf_primary_version = -1;
static int hf_primary_bundle_flags = -1;
static int hf_primary_bundle_flags_deletion_report = -1;
static int hf_primary_bundle_flags_delivery_report = -1;
static int hf_primary_bundle_flags_forwarding_report = -1;
static int hf_primary_bundle_flags_reception_report = -1;
static int hf_primary_bundle_flags_contains_manifest = -1;
static int hf_primary_bundle_flags_req_status_time = -1;
static int hf_primary_bundle_flags_user_app_ack = -1;
static int hf_primary_bundle_flags_no_fragment = -1;
static int hf_primary_bundle_flags_payload_admin = -1;
static int hf_primary_bundle_flags_is_fragment = -1;
static int hf_primary_crc_type = -1;
static int hf_primary_dst_eid = -1;
static int hf_primary_src_eid = -1;
static int hf_primary_report_eid = -1;
static int hf_primary_create_ts = -1;
static int hf_primary_create_ts_dtntime = -1;
static int hf_primary_create_ts_utctime = -1;
static int hf_primary_create_ts_seqno = -1;
static int hf_primary_lifetime = -1;
static int hf_primary_frag_offset = -1;
static int hf_primary_crc_value = -1;
static int hf_primary_crc_value16 = -1;
static int hf_primary_crc_value32 = -1;

static int hf_canonical_type_code = -1;
static int hf_canonical_block_num = -1;
static int hf_canonical_block_flags = -1;
static int hf_canonical_block_flags_delete_no_process = -1;
static int hf_canonical_block_flags_status_no_process = -1;
static int hf_canonical_block_flags_remove_no_process = -1;
static int hf_canonical_block_flags_replicate_in_fragment = -1;
static int hf_canonical_crc_type = -1;
static int hf_canonical_data = -1;
static int hf_canonical_data_len = -1;
static int hf_canonical_crc_value = -1;
static int hf_canonical_crc_value16 = -1;
static int hf_canonical_crc_value32 = -1;

static int hf_payload = -1;
static int hf_previous_node_eid = -1;
static int hf_bundle_age_time = -1;

/// Field definitions
static hf_register_info fields[] = {
    {&hf_bundle, {"Bundle Protocol Version 7", "bpv7", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_block, {"Block", "bpv7.block", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_primary_version, {"Version", "bpv7.primary.version", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_bundle_flags, {"Bundle Flags", "bpv7.primary.bundle_flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_bundle_flags_deletion_report, {"Deletion Report", "bpv7.primary.bundle_flags.deleteion_report", FT_UINT16, BASE_DEC, NULL, BP_BUNDLE_REQ_DELETION_REPORT, NULL, HFILL}},
    {&hf_primary_bundle_flags_delivery_report, {"Delivery Report", "bpv7.primary.bundle_flags.delivery_report", FT_UINT16, BASE_DEC, NULL, BP_BUNDLE_REQ_DELIVERY_REPORT, NULL, HFILL}},
    {&hf_primary_bundle_flags_forwarding_report, {"Forwarding Report", "bpv7.primary.bundle_flags.forwarding_report", FT_UINT16, BASE_DEC, NULL, BP_BUNDLE_REQ_FORWARDING_REPORT, NULL, HFILL}},
    {&hf_primary_bundle_flags_reception_report, {"Reception Report", "bpv7.primary.bundle_flags.reception_report", FT_UINT16, BASE_DEC, NULL, BP_BUNDLE_REQ_RECEPTION_REPORT, NULL, HFILL}},
    {&hf_primary_bundle_flags_contains_manifest, {"Contains Manifest", "bpv7.primary.bundle_flags.contains_manifest", FT_UINT16, BASE_DEC, NULL, BP_BUNDLE_CONTAINS_MANIFEST, NULL, HFILL}},
    {&hf_primary_bundle_flags_req_status_time, {"Request Status time", "bpv7.primary.bundle_flags.req_status_time", FT_UINT16, BASE_DEC, NULL, BP_BUNDLE_REQ_STATUS_TIME, NULL, HFILL}},
    {&hf_primary_bundle_flags_user_app_ack, {"User App. Ack.", "bpv7.primary.bundle_flags.user_app_ack", FT_UINT16, BASE_DEC, NULL, BP_BUNDLE_USER_APP_ACK, NULL, HFILL}},
    {&hf_primary_bundle_flags_no_fragment, {"No Fragment", "bpv7.primary.bundle_flags.no_fragment", FT_UINT16, BASE_DEC, NULL, BP_BUNDLE_NO_FRAGMENT, NULL, HFILL}},
    {&hf_primary_bundle_flags_payload_admin, {"Payload is Administrative", "bpv7.primary.bundle_flags.payload_admin", FT_UINT16, BASE_DEC, NULL, BP_BUNDLE_PAYLOAD_ADMIN, NULL, HFILL}},
    {&hf_primary_bundle_flags_is_fragment, {"Is Fragment", "bpv7.primary.bundle_flags.is_fragment", FT_UINT16, BASE_DEC, NULL, BP_BUNDLE_IS_FRAGMENT, NULL, HFILL}},
    {&hf_primary_crc_type, {"CRC Type", "bpv7.primary.crc_type", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_dst_eid, {"Destination EID", "bpv7.primary.dst_eid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_src_eid, {"Source EID", "bpv7.primary.src_eid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_report_eid, {"Report-to EID", "bpv7.primary.report_eid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_create_ts, {"Creation Timestamp", "bpv7.primary.create_ts", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_create_ts_dtntime, {"DTN Time", "bpv7.primary.create_ts.dtntime", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_create_ts_utctime, {"UTC Time", "bpv7.primary.create_ts.utctime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_create_ts_seqno, {"Sequence Number", "bpv7.primary.create_ts.seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_lifetime, {"Lifetime (us)", "bpv7.primary.lifetime", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_frag_offset, {"Fragment Offset", "bpv7.primary.frag_offset", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_crc_value, {"CRC Value", "bpv7.primary.crc_value", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_crc_value16, {"CRC Value", "bpv7.primary.crc_value16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_crc_value32, {"CRC Value", "bpv7.primary.crc_value32", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

    {&hf_canonical_type_code, {"Type Code", "bpv7.canonical.type_code", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_block_num, {"Block Number", "bpv7.canonical.block_num", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_block_flags, {"Block Flags", "bpv7.canonical.block_flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_block_flags_delete_no_process, {"Delete if not processed", "bpv7.canonical.block_flags.delete_if_no_process", FT_UINT16, BASE_DEC, NULL, BP_BLOCK_DELETE_IF_NO_PROCESS, NULL, HFILL}},
    {&hf_canonical_block_flags_status_no_process, {"Status if not processed", "bpv7.canonical.block_flags.status_if_no_process", FT_UINT16, BASE_DEC, NULL, BP_BLOCK_STATUS_IF_NO_PROCESS, NULL, HFILL}},
    {&hf_canonical_block_flags_remove_no_process, {"Remove if not processed", "bpv7.canonical.block_flags.remove_if_no_process", FT_UINT16, BASE_DEC, NULL, BP_BLOCK_REMOVE_IF_NO_PROCESS, NULL, HFILL}},
    {&hf_canonical_block_flags_replicate_in_fragment, {"Replicate in fragment", "bpv7.canonical.block_flags.replicate_in_fragment", FT_UINT16, BASE_DEC, NULL, BP_BLOCK_REPLICATE_IN_FRAGMENT, NULL, HFILL}},
    {&hf_canonical_crc_type, {"CRC Type", "bpv7.canonical.crc_type", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_data, {"Block Data", "bpv7.canonical.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_data_len, {"Data Length (octets)", "bpv7.canonical.data_len", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_crc_value, {"CRC Value", "bpv7.canonical.crc_value", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_crc_value16, {"CRC Value", "bpv7.canonical.crc_value16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_crc_value32, {"CRC Value", "bpv7.canonical.crc_value32", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

    {&hf_payload, {"BP Payload", "bpv7.payload", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_previous_node_eid, {"Previous Node EID", "bpv7.previous_node.eid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_bundle_age_time, {"Bundle Age (us)", "bpv7.bundle_age.time", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},

};

static const int *bundle_flags[] = {
    &hf_primary_bundle_flags_deletion_report,
    &hf_primary_bundle_flags_delivery_report,
    &hf_primary_bundle_flags_forwarding_report,
    &hf_primary_bundle_flags_reception_report,
    &hf_primary_bundle_flags_contains_manifest,
    &hf_primary_bundle_flags_req_status_time,
    &hf_primary_bundle_flags_user_app_ack,
    &hf_primary_bundle_flags_no_fragment,
    &hf_primary_bundle_flags_payload_admin,
    &hf_primary_bundle_flags_is_fragment,
    NULL
};

static const int *block_flags[] = {
    &hf_canonical_block_flags_delete_no_process,
    &hf_canonical_block_flags_status_no_process,
    &hf_canonical_block_flags_remove_no_process,
    &hf_canonical_block_flags_replicate_in_fragment,
    NULL
};

static int ett_bundle = -1;
static int ett_bundle_flags = -1;
static int ett_block = -1;
static int ett_primary_create_ts = -1;
static int ett_block_flags = -1;
static int ett_payload = -1;
static int *ett[] = {
    &ett_bundle,
    &ett_bundle_flags,
    &ett_block,
    &ett_primary_create_ts,
    &ett_block_flags,
    &ett_payload,
};

static expert_field ei_cbor_invalid = EI_INIT;
static expert_field ei_cbor_wrong_type = EI_INIT;
static expert_field ei_array_wrong_size = EI_INIT;
static expert_field ei_item_missing = EI_INIT;
static expert_field ei_invalid_bp_version = EI_INIT;
static expert_field ei_block_type_unknown = EI_INIT;
static expert_field ei_block_num_primary = EI_INIT;
static expert_field ei_block_partial_decode = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_cbor_invalid, { "bpv7.cbor_invalid", PI_MALFORMED, PI_ERROR, "CBOR cannot be decoded", EXPFILL}},
    {&ei_cbor_wrong_type, { "bpv7.cbor_wrong_type", PI_MALFORMED, PI_ERROR, "CBOR is wrong type", EXPFILL}},
    {&ei_array_wrong_size, { "bpv7.array_wrong_size", PI_MALFORMED, PI_ERROR, "CBOR array is the wrong size", EXPFILL}},
    {&ei_item_missing, { "bpv7.item_missing", PI_MALFORMED, PI_ERROR, "CBOR item is missing or incorrect type", EXPFILL}},
    {&ei_invalid_bp_version, { "bpv7.invalid_bp_version", PI_PROTOCOL, PI_WARN, "Invalid BP version", EXPFILL}},
    {&ei_block_type_unknown, { "bpv7.block_type_unknown", PI_UNDECODED, PI_WARN, "Unknown block type code", EXPFILL}},
    {&ei_block_num_primary, { "bpv7.block_num_primary", PI_PROTOCOL, PI_WARN, "Invalid primary block number", EXPFILL}},
    {&ei_block_partial_decode, { "bpv7.block_partial_decode", PI_UNDECODED, PI_WARN, "Block data not fully dissected", EXPFILL}},
};

bp_block_primary_t * bp_block_primary_new() {
    bp_block_primary_t *obj = wmem_new0(wmem_file_scope(), bp_block_primary_t);
    return obj;
}

void bp_block_primary_delete(gpointer ptr) {
    //bp_block_primary_t *obj = (bp_block_primary_t *)ptr;
    wmem_free(wmem_file_scope(), ptr);
}

bp_block_canonical_t * bp_block_canonical_new() {
    bp_block_canonical_t *obj = wmem_new0(wmem_file_scope(), bp_block_canonical_t);
    return obj;
}

void bp_block_canonical_delete(gpointer ptr) {
    //bp_bundle_t *obj = (bp_bundle_t *)ptr;
    wmem_free(wmem_file_scope(), ptr);
}

bp_bundle_t * bp_bundle_new() {
    bp_bundle_t *obj = wmem_new(wmem_file_scope(), bp_bundle_t);
    obj->primary = bp_block_primary_new();
    obj->blocks = g_sequence_new(bp_block_canonical_delete);
    return obj;
}

void bp_bundle_delete(gpointer ptr) {
    bp_bundle_t *obj = (bp_bundle_t *)ptr;
    bp_block_primary_delete(obj->primary);
    g_sequence_free(obj->blocks);
    wmem_free(wmem_file_scope(), ptr);
}

static cbor_item_t * cbor_array_get_safe(const cbor_item_t *array, size_t index) {
    if (cbor_array_size(array) <= index) {
        return NULL;
    }
    return cbor_array_get(array, index);
}

static guint64 * cbor_require_uint64(const cbor_item_t *item) {
    if (!item) {
        return NULL;
    }
    switch (item->type) {
        case CBOR_TYPE_UINT: {
            guint64 *result = wmem_new(wmem_file_scope(), guint64);
            *result = cbor_get_int(item);
            return result;
        }
        default:
            return NULL;
    }
}

static gint64 * cbor_require_int64(const cbor_item_t *item) {
    if (!item) {
        return NULL;
    }
    switch (item->type) {
        case CBOR_TYPE_UINT: {
            gint64 *result = wmem_new(wmem_file_scope(), gint64);
            *result = cbor_get_int(item);
            return result;
        }
        case CBOR_TYPE_NEGINT: {
            const guint64 negval = cbor_get_int(item);
            gint64 *result = wmem_new(wmem_file_scope(), gint64);
            *result = -negval - 1;
            return result;

        }
        default:
            return NULL;
    }
}

static tvbuff_t * cbor_require_string(tvbuff_t *parent, const cbor_item_t *item) {
    if (!item) {
        return NULL;
    }

    size_t len = 0;
    guint8 *buf = NULL;

    switch (item->type) {
        case CBOR_TYPE_BYTESTRING:
            len = cbor_bytestring_length(item);
            buf = wmem_alloc(wmem_file_scope(), len);
            memcpy(buf, cbor_bytestring_handle(item), len);
            break;
        case CBOR_TYPE_STRING:
            len = cbor_string_length(item);
            buf = wmem_alloc(wmem_file_scope(), len);
            memcpy(buf, cbor_string_handle(item), len);
            break;
        default:
            return NULL;
    }

    tvbuff_t *result = tvb_new_child_real_data(parent, buf, len, len);
    return result;
}

static proto_item * proto_tree_add_cbor_uint64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const guint64 *value) {
    proto_item *item = proto_tree_add_uint64(tree, hfindex, tvb, 0, 0, value ? *value : 0);
    if (!value) {
        expert_add_info(pinfo, item, &ei_item_missing);
    }
    return item;
}

static proto_item * proto_tree_add_cbor_int64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const gint64 *value) {
    proto_item *item = proto_tree_add_int64(tree, hfindex, tvb, 0, 0, value ? *value : 0);
    if (!value) {
        expert_add_info(pinfo, item, &ei_item_missing);
    }
    return item;
}

static proto_item * proto_tree_add_cbor_bitmask64(proto_tree *tree, int hfindex, const gint ett, const int **fields, packet_info *pinfo, tvbuff_t *tvb, const guint64 *value) {
    proto_item *item = proto_tree_add_bitmask_value(tree, tvb, 0, hfindex, ett, fields, value ? *value : 0);
    if (!value) {
        expert_add_info(pinfo, item, &ei_item_missing);
    }
    return item;
}

static proto_item * proto_tree_add_cbor_textstring(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb) {
    const gchar *value = NULL;
    if (tvb) {
        value = tvb_memdup(wmem_packet_scope(), tvb, 0, tvb_captured_length(tvb));
    }
    proto_item *item = proto_tree_add_string(tree, hfindex, tvb, 0, tvb_captured_length(tvb), value);
    if (!tvb) {
        expert_add_info(pinfo, item, &ei_item_missing);
    }
    return item;
}

static proto_item * proto_tree_add_crc(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, guint64 crc_type _U_, const guint64 *crc_value) {
    proto_item *item;
    switch (crc_type) {
        case BP_CRC_16:
        case BP_CRC_32:
            item = proto_tree_add_uint(tree, hfindex, tvb, 0, 0, crc_value ? *crc_value : 0);
            break;
        default:
            item = NULL;
            break;
    }
    if (!crc_value) {
        expert_add_info(pinfo, item, &ei_item_missing);
    }
    return item;
}

static int dissect_bp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    const guint buflen = tvb_captured_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BPv7");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item_bundle = proto_tree_add_item(tree, hf_bundle, tvb, 0, 0, ENC_NA);
    proto_tree *tree_bundle = proto_item_add_subtree(item_bundle, ett_bundle);

    bp_bundle_t *bundle = bp_bundle_new();

    /* Load the whole bundle at-once and extract parts below. */
    void *buf = tvb_memdup(wmem_packet_scope(), tvb, 0, buflen);
    struct cbor_load_result load_result;
    cbor_item_t *cbor_root = cbor_load(buf, buflen, &load_result);
    proto_item_set_len(item_bundle, load_result.read);
    if (!cbor_root) {
        expert_add_info_format(pinfo, item_bundle, &ei_cbor_invalid, "Bundle is invalid");
    }
    else if (cbor_root->type != CBOR_TYPE_ARRAY) {
        expert_add_info_format(pinfo, item_bundle, &ei_cbor_wrong_type, "Bundle has type %d", cbor_root->type);
    }
    else if (cbor_array_size(cbor_root) < 1) {
        expert_add_info_format(pinfo, item_bundle, &ei_array_wrong_size, "Bundle has %" PRIu64 " items", cbor_array_size(cbor_root));
    }
    else {
        const size_t bundle_len = cbor_array_size(cbor_root);
        for (size_t block_ix = 0; block_ix < bundle_len; ++block_ix) {
            proto_item *item_block = proto_tree_add_item(tree_bundle, hf_block, tvb, 0, 0, ENC_NA);
            proto_tree *tree_block = proto_item_add_subtree(item_block, ett_block);

            cbor_item_t *cbor_block = cbor_array_get(cbor_root, block_ix);
            if (!cbor_block) {
                expert_add_info_format(pinfo, item_block, &ei_cbor_invalid, "Block is invalid");
                continue;
            }
            const size_t block_size = cbor_array_size(cbor_block);
            proto_item_append_text(item_block, ", Count: %" PRIu64, block_size);

            if (block_ix == 0) {
                // Primary block
                proto_item_prepend_text(item_block, "Primary ");

                if (cbor_block->type != CBOR_TYPE_ARRAY) {
                    expert_add_info_format(pinfo, item_block, &ei_cbor_wrong_type, "Block has type %d", cbor_block->type);
                }
                else if (block_size < 8) {
                    expert_add_info_format(pinfo, item_block, &ei_array_wrong_size, "Block has %" PRIu64 " items", block_size);
                }
                else {
                    size_t field_ix = 0;
                    bp_block_primary_t *block = bp_block_primary_new();

                    const guint64 *version = cbor_require_uint64(cbor_array_get(cbor_block, field_ix++));
                    proto_item *item_version = proto_tree_add_cbor_uint64(tree_block, hf_primary_version, pinfo, tvb, version);
                    if (version && (*version != 7)) {
                        expert_add_info(pinfo, item_version, &ei_invalid_bp_version);
                    }

                    const guint64 *flags = cbor_require_uint64(cbor_array_get(cbor_block, field_ix++));
                    proto_tree_add_cbor_bitmask64(tree_block, hf_primary_bundle_flags, ett_bundle_flags, bundle_flags, pinfo, tvb, flags);
                    block->flags = flags;

                    const guint64 *crc_type = cbor_require_uint64(cbor_array_get(cbor_block, field_ix++));
                    proto_tree_add_cbor_uint64(tree_block, hf_primary_crc_type, pinfo, tvb, crc_type);
                    block->crc_type = crc_type;

                    tvbuff_t *tvb_dst_eid = cbor_require_string(tvb, cbor_array_get(cbor_block, field_ix++));
                    proto_tree_add_cbor_textstring(tree_block, hf_primary_dst_eid, pinfo, tvb_dst_eid);
                    block->dst_eid = tvb_dst_eid;

                    tvbuff_t *tvb_src_eid = cbor_require_string(tvb, cbor_array_get(cbor_block, field_ix++));
                    proto_tree_add_cbor_textstring(tree_block, hf_primary_src_eid, pinfo, tvb_src_eid);
                    block->src_eid = tvb_src_eid;

                    tvbuff_t *tvb_rep_eid = cbor_require_string(tvb, cbor_array_get(cbor_block, field_ix++));
                    proto_tree_add_cbor_textstring(tree_block, hf_primary_report_eid, pinfo, tvb_rep_eid);
                    block->rep_eid = tvb_rep_eid;

                    // Complex type
                    cbor_item_t *cbor_create_ts = cbor_array_get_safe(cbor_block, field_ix++);
                    proto_item *item_ts = proto_tree_add_item(tree_block, hf_primary_create_ts, tvb, 0, 0, ENC_NA);
                    if (!cbor_create_ts) {
                        expert_add_info(pinfo, item_ts, &ei_item_missing);
                    }
                    else {
                        proto_tree *tree_ts = proto_item_add_subtree(item_ts, ett_primary_create_ts);

                        if (cbor_create_ts->type != CBOR_TYPE_ARRAY) {
                            expert_add_info_format(pinfo, item_ts, &ei_cbor_wrong_type, "Timestamp has type %d", cbor_create_ts->type);
                        }
                        else if (cbor_array_size(cbor_create_ts) != 2) {
                            expert_add_info_format(pinfo, item_ts, &ei_array_wrong_size, "Timestamp has %" PRIu64 " items", cbor_array_size(cbor_create_ts));
                        }
                        else {
                            const gint64 *dtntime = cbor_require_int64(cbor_array_get_safe(cbor_create_ts, 0));
                            proto_tree_add_cbor_int64(tree_ts, hf_primary_create_ts_dtntime, pinfo, tvb, dtntime);

                            if (dtntime) {
                                // Offset from Section 4.1.6
                                nstime_t utctime;
                                utctime.secs = 946684800 + *dtntime;
                                utctime.nsecs = 0;
                                proto_item *item_utctime = proto_tree_add_time(tree_ts, hf_primary_create_ts_utctime, tvb, 0, 0, &utctime);
                                PROTO_ITEM_SET_GENERATED(item_utctime);
                            }

                            const guint64 *seqno = cbor_require_uint64(cbor_array_get_safe(cbor_create_ts, 1));
                            proto_tree_add_cbor_uint64(tree_ts, hf_primary_create_ts_seqno, pinfo, tvb, seqno);
                        }
                    }

                    const guint64 *lifetime = cbor_require_uint64(cbor_array_get(cbor_block, field_ix++));
                    proto_tree_add_cbor_uint64(tree_block, hf_primary_lifetime, pinfo, tvb, lifetime);

                    // optional items
                    if (flags && (*flags & BP_BUNDLE_IS_FRAGMENT)) {
                        const guint64 *frag_offset = cbor_require_uint64(cbor_array_get_safe(cbor_block, field_ix++));
                        proto_tree_add_cbor_uint64(tree_block, hf_primary_frag_offset, pinfo, tvb, frag_offset);
                    }
                    if (crc_type && (*crc_type != 0)) {
                        const int hf_crc = (*crc_type == BP_CRC_16 ? hf_primary_crc_value16 : hf_primary_crc_value32);
                        const guint64 *crc_value = cbor_require_uint64(cbor_array_get_safe(cbor_block, field_ix++));
                        proto_tree_add_crc(tree_block, hf_crc, pinfo, tvb, *crc_type, crc_value);
                        block->crc_value = crc_value;
                    }

                    bundle->primary = block;
                }
            }
            else {
                // Non-primary block
                if (cbor_block->type != CBOR_TYPE_ARRAY) {
                    expert_add_info_format(pinfo, item_block, &ei_cbor_wrong_type, "Block has type %d", cbor_block->type);
                }
                else if (block_size < 5) {
                    expert_add_info_format(pinfo, item_block, &ei_array_wrong_size, "Block has %" PRIu64 " items", block_size);
                }
                else {
                    size_t field_ix = 0;
                    bp_block_canonical_t *block = bp_block_canonical_new();

                    const guint64 *type_code = cbor_require_uint64(cbor_array_get(cbor_block, field_ix++));
                    proto_item *item_type = proto_tree_add_cbor_uint64(tree_block, hf_canonical_type_code, pinfo, tvb, type_code);
                    block->type_code = type_code;
                    proto_item_append_text(item_block, ", Type: %" PRIu64, *type_code);

                    const guint64 *block_num = cbor_require_uint64(cbor_array_get(cbor_block, field_ix++));
                    proto_tree_add_cbor_uint64(tree_block, hf_canonical_block_num, pinfo, tvb, block_num);
                    block->block_number = block_num;

                    const guint64 *flags = cbor_require_uint64(cbor_array_get(cbor_block, field_ix++));
                    proto_tree_add_cbor_bitmask64(tree_block, hf_canonical_block_flags, ett_block_flags, block_flags, pinfo, tvb, flags);
                    block->flags = flags;

                    const guint64 *crc_type = cbor_require_uint64(cbor_array_get(cbor_block, field_ix++));
                    proto_tree_add_cbor_uint64(tree_block, hf_canonical_crc_type, pinfo, tvb, crc_type);
                    block->crc_type = crc_type;

                    tvbuff_t *tvb_data = cbor_require_string(tvb, cbor_array_get(cbor_block, field_ix++));
                    dissector_handle_t data_dissect = NULL;
                    if (type_code) {
                        data_dissect = dissector_get_uint_handle(block_dissector, *type_code);
                    }
                    block->data = tvb_data;

                    if (crc_type && (*crc_type != 0)) {
                        const int hf_crc = (*crc_type == BP_CRC_16 ? hf_canonical_crc_value16 : hf_canonical_crc_value32);
                        const guint64 *crc_value = cbor_require_uint64(cbor_array_get_safe(cbor_block, field_ix++));
                        proto_tree_add_crc(tree_block, hf_crc, pinfo, tvb, *crc_type, crc_value);
                        block->crc_value = crc_value;
                    }

                    proto_item *item_len = proto_tree_add_uint64(tree_block, hf_canonical_data_len, tvb, 0, 0, tvb_captured_length(tvb_data));
                    PROTO_ITEM_SET_GENERATED(item_len);
                    add_new_data_source(pinfo, tvb, "Block Data");

                    // sub-dissect after all is read
                    if (!data_dissect) {
                        expert_add_info(pinfo, item_type, &ei_block_type_unknown);
                        call_data_dissector(tvb_data, pinfo, tree_block);
                    }
                    else {
                        block_dissector_data_t dissect_data;
                        dissect_data.bundle = bundle;
                        dissect_data.block = block;
                        const int sublen = call_dissector_with_data(data_dissect, tvb_data, pinfo, tree_block, &dissect_data);
                        if ((sublen < 0) || ((guint)sublen < tvb_captured_length(tvb_data))) {
                            expert_add_info(pinfo, tree_block, &ei_block_partial_decode);
                        }
                    }

                    g_sequence_append(bundle->blocks, block);
                }
            }
            cbor_decref(&cbor_block);
        }
    }

    cbor_decref(&cbor_root);
    wmem_free(wmem_packet_scope(), buf);
    bp_bundle_delete(bundle);
    return load_result.read;
}

static void reinit_bp(void) {
}

/** Dissector for Bundle Payload block.
 */
static int dissect_block_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    block_dissector_data_t *context = (block_dissector_data_t *)data;
    if (!context) {
        return -1;
    }
    const guint buflen = tvb_captured_length(tvb);

    if (context->block->block_number && (*(context->block->block_number) != 0)) {
        expert_add_info(pinfo, tree, &ei_block_num_primary);
    }

    // Back up to top-level
    proto_item *parent = proto_item_get_parent_nth(tree, 2);
    // Visible in new source
    //add_new_data_source(pinfo, tvb, "Bundle Payload");
    proto_item_prepend_text(proto_tree_get_parent(tree), "Payload ");

    const gchar *eid = NULL;
    if (context->bundle->primary->dst_eid) {
        eid = tvb_memdup(wmem_packet_scope(), context->bundle->primary->dst_eid, 0, tvb_captured_length(context->bundle->primary->dst_eid));
    }

    dissector_handle_t payload_dissect = dissector_get_string_handle(payload_dissector, eid);
    if (!payload_dissect) {
        call_data_dissector(tvb, pinfo, parent);
    }
    else {
        call_dissector_with_data(payload_dissect, tvb, pinfo, parent, &data);
    }

    return buflen;
}

/** Dissector for Previous Node block.
 */
static int dissect_block_prev_node(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    const guint buflen = tvb_captured_length(tvb);
    //proto_item *item_block = proto_tree_get_parent(tree);

    /* Load the whole bundle at-once and extract parts below. */
    void *buf = tvb_memdup(wmem_packet_scope(), tvb, 0, buflen);
    struct cbor_load_result load_result;
    cbor_item_t *cbor_root = cbor_load(buf, buflen, &load_result);

    tvbuff_t *tvb_eid = cbor_require_string(tvb, cbor_root);
    proto_tree_add_cbor_textstring(tree, hf_previous_node_eid, pinfo, tvb_eid);

    return load_result.read;
}

/** Dissector for Previous Node block.
 */
static int dissect_block_bundle_age(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    const guint buflen = tvb_captured_length(tvb);
    //proto_item *item_block = proto_tree_get_parent(tree);

    /* Load the whole bundle at-once and extract parts below. */
    void *buf = tvb_memdup(wmem_packet_scope(), tvb, 0, buflen);
    struct cbor_load_result load_result;
    cbor_item_t *cbor_root = cbor_load(buf, buflen, &load_result);

    const guint64 *age = cbor_require_uint64(cbor_root);
    proto_tree_add_cbor_uint64(tree, hf_bundle_age_time, pinfo, tvb, age);

    return load_result.read;
}

static void proto_register_bp(void) {
    proto_bp = proto_register_protocol(
        "DTN Bundle Protocol Version 7", /* name */
        "BPv7", /* short name */
        "bpv7" /* abbrev */
    );

    proto_register_field_array(proto_bp, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_bp);
    expert_register_field_array(expert, expertitems, array_length(expertitems));
    handle_bp = register_dissector("bpv7", dissect_bp, proto_bp);

    block_dissector = register_dissector_table("bpv7.block_type", "BPv7 Block Extension", proto_bp, FT_UINT32, BASE_HEX);
    payload_dissector = register_dissector_table("bpv7.payload", "BPv7 Payload", proto_bp, FT_STRING, BASE_NONE);

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

    /* Packaged extensions */
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_block_payload, proto_bp);
        dissector_add_uint("bpv7.block_type", 1, hdl);
    }
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_block_prev_node, proto_bp);
        dissector_add_uint("bpv7.block_type", 7, hdl);
    }
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_block_bundle_age, proto_bp);
        dissector_add_uint("bpv7.block_type", 8, hdl);
    }

    reinit_bp();
}

const char plugin_version[] = "0.0";

const char plugin_release[] = "2.6";

void plugin_register(void) {
    static proto_plugin plugin_bp;
    plugin_bp.register_protoinfo = proto_register_bp;
    plugin_bp.register_handoff = proto_reg_handoff_bp;
    proto_register_plugin(&plugin_bp);
}
