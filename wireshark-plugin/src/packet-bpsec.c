#include "packet-bpsec.h"
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

/// Glib logging "domain" name
//static const char *LOG_DOMAIN = "bpsec";

/// Protocol handles
static int proto_bpsec = -1;

/// Dissect opaque CBOR parameters/results
static dissector_table_t dissect_media = NULL;

static int hf_bib = -1;
static int hf_bcb = -1;
static int hf_asb_target_list = -1;
static int hf_asb_target = -1;
static int hf_asb_ctxid = -1;
static int hf_asb_flags = -1;
static int hf_asb_flags_has_params = -1;
static int hf_asb_flags_has_secsrc = -1;
static int hf_asb_secsrc = -1;
static int hf_asb_param_list = -1;
static int hf_asb_param_pair = -1;
static int hf_asb_param_id = -1;
static int hf_asb_result_all_list = -1;
static int hf_asb_result_tgt_list = -1;
static int hf_asb_result_pair = -1;
static int hf_asb_result_id = -1;
/// Field definitions
static hf_register_info fields[] = {
    {&hf_bib, {"BPSec Block Integrity Block", "bpsec.bib", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_bcb, {"BPSec Block Confidentiality Block", "bpsec.bcb", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_asb_target_list, {"Security Targets, Count", "bpsec.asb.target_count", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_asb_target, {"Target Block Number", "bpsec.asb.target", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_asb_ctxid, {"Context ID", "bpsec.asb.ctxid", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_asb_flags, {"Flags", "bpv7.asb.flags", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_asb_flags_has_params, {"Parameters Present", "bpv7.asb.flags.has_params", FT_UINT8, BASE_DEC, NULL, ASB_HAS_PARAMS, NULL, HFILL}},
    {&hf_asb_flags_has_secsrc, {"Security Source Present", "bpv7.asb.flags.has_secsrc", FT_UINT8, BASE_DEC, NULL, ASB_HAS_SOURCE, NULL, HFILL}},
    {&hf_asb_secsrc, {"Security Source", "bpsec.asb.secsrc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_asb_param_list, {"Security Parameters, Count", "bpsec.asb.param_count", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_asb_param_pair, {"Parameter", "bpsec.asb.param", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_asb_param_id, {"Type ID", "bpsec.asb.param.id", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_asb_result_all_list, {"Security Result Targets, Count", "bpsec.asb.result_count", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_asb_result_tgt_list, {"Security Results, Count", "bpsec.asb.result_count", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_asb_result_pair, {"Result", "bpsec.asb.result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_asb_result_id, {"Type ID", "bpsec.asb.result.id", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
};

static const int *asb_flags[] = {
    &hf_asb_flags_has_params,
    &hf_asb_flags_has_secsrc,
    NULL
};

static int ett_asb = -1;
static int ett_asb_flags = -1;
static int ett_tgt_list = -1;
static int ett_param_list = -1;
static int ett_param_pair = -1;
static int ett_result_all_list = -1;
static int ett_result_tgt_list = -1;
static int ett_result_pair = -1;
/// Tree structures
static int *ett[] = {
    &ett_asb,
    &ett_asb_flags,
    &ett_tgt_list,
    &ett_param_list,
    &ett_param_pair,
    &ett_result_all_list,
    &ett_result_tgt_list,
    &ett_result_pair,
};

static expert_field ei_secsrc_diff = EI_INIT;
static expert_field ei_ctxid_zero = EI_INIT;
static expert_field ei_ctxid_priv = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_secsrc_diff, {"bpsec.secsrc_diff", PI_SECURITY, PI_CHAT, "BPSec Security Source different from bundle Source", EXPFILL}},
    {&ei_ctxid_zero, {"bpsec.ctxid_zero", PI_SECURITY, PI_WARN, "BPSec Security Context ID zero is reserved", EXPFILL}},
    {&ei_ctxid_priv, {"bpsec.ctxid_priv", PI_SECURITY, PI_NOTE, "BPSec Security Context ID from private/experimental block", EXPFILL}},
};

/** Dissector for Bundle Integrity block.
 */
static int dissect_block_asb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const bp_dissector_data_t *const data, int root_hfindex) {
    proto_item *item_asb = proto_tree_add_item(tree, root_hfindex, tvb, 0, 0, ENC_NA);
    proto_tree *tree_asb = proto_item_add_subtree(item_asb, ett_asb);
    gint offset = 0;

    bp_cbor_chunk_t *chunk_asb = cbor_require_array_with_size(tvb, pinfo, tree_asb, &offset, 4, 6);
    if (!chunk_asb) {
        return offset;
    }

    GArray *targets;
    targets = g_array_new(FALSE, FALSE, sizeof(guint64));

    const gint offset_tgt_list = offset;
    bp_cbor_chunk_t *chunk_tgt_list = cbor_require_array(tvb, pinfo, tree_asb, &offset);
    if (chunk_tgt_list) {
        proto_item *item_tgt_list = proto_tree_add_int64(tree_asb, hf_asb_target_list, tvb, offset_tgt_list, 0, chunk_tgt_list->head_value);
        proto_tree *tree_tgt_list = proto_item_add_subtree(item_tgt_list, ett_tgt_list);

        bp_cbor_chunk_t *chunk_tgt = bp_scan_cbor_chunk(tvb, offset);
        guint64 *tgt_blknum = cbor_require_uint64(chunk_tgt);
        proto_tree_add_cbor_uint64(tree_tgt_list, hf_asb_target, pinfo, tvb, chunk_tgt, tgt_blknum);
        offset += chunk_tgt->data_length;
        if (tgt_blknum) {
            g_array_append_vals(targets, tgt_blknum, 1);
        }
        bp_cbor_require_delete(tgt_blknum);
        bp_cbor_chunk_delete(chunk_tgt);

        proto_item_set_len(item_tgt_list, offset - offset_tgt_list);
        bp_cbor_chunk_delete(chunk_tgt_list);
    }

    bp_cbor_chunk_t *chunk_ctxid = bp_scan_cbor_chunk(tvb, offset);
    gint64 *ctxid = cbor_require_int64(chunk_ctxid);
    proto_item *item_ctxid = proto_tree_add_cbor_int64(tree_asb, hf_asb_ctxid, pinfo, tvb, chunk_ctxid, ctxid);
    offset += chunk_ctxid->data_length;
    if (ctxid) {
        if (*ctxid == 0) {
            expert_add_info(pinfo, item_ctxid, &ei_ctxid_zero);
        }
        else if (*ctxid < 0) {
            expert_add_info(pinfo, item_ctxid, &ei_ctxid_priv);
        }
    }
    bp_cbor_require_delete(ctxid);
    bp_cbor_chunk_delete(chunk_ctxid);

    bp_cbor_chunk_t *chunk_flags = bp_scan_cbor_chunk(tvb, offset);
    guint64 *flags = cbor_require_uint64(chunk_flags);
    proto_tree_add_cbor_bitmask(tree_asb, hf_asb_flags, ett_asb_flags, asb_flags, pinfo, tvb, chunk_flags, flags);
    offset += chunk_flags->data_length;
    bp_cbor_chunk_delete(chunk_flags);

    if (flags && (*flags & ASB_HAS_SOURCE)) {
        bp_eid_t *secsrc = bp_eid_new();
        proto_item *item_secsrc = proto_tree_add_cbor_eid(tree_asb, hf_asb_secsrc, pinfo, tvb, &offset, secsrc);
        if (!bp_eid_equal(data->bundle->primary->src_nodeid, secsrc)) {
            expert_add_info(pinfo, item_secsrc, &ei_secsrc_diff);
        }
        bp_eid_delete(secsrc);
    }

    if (flags && (*flags & ASB_HAS_PARAMS)) {
        const gint offset_param_list = offset;
        bp_cbor_chunk_t *chunk_param_list = cbor_require_array(tvb, pinfo, tree_asb, &offset);
        if (chunk_param_list) {
            proto_item *item_param_list = proto_tree_add_int64(tree_asb, hf_asb_param_list, tvb, offset_param_list, 0, chunk_param_list->head_value);
            proto_tree *tree_param_list = proto_item_add_subtree(item_param_list, ett_param_list);

            const gint offset_param_pair = offset;
            bp_cbor_chunk_t *chunk_param_pair = cbor_require_array_with_size(tvb, pinfo, tree_asb, &offset, 2, 2);
            if (chunk_param_pair) {
                proto_item *item_param_pair = proto_tree_add_item(tree_param_list, hf_asb_param_pair, tvb, offset_param_pair, 0, ENC_NA);
                proto_tree *tree_param_pair = proto_item_add_subtree(item_param_pair, ett_param_pair);

                bp_cbor_chunk_t *chunk_paramid = bp_scan_cbor_chunk(tvb, offset);
                gint64 *paramid = cbor_require_int64(chunk_paramid);
                proto_tree_add_cbor_int64(tree_param_pair, hf_asb_param_id, pinfo, tvb, chunk_paramid, paramid);
                offset += chunk_paramid->data_length;
                if (paramid) {
                    proto_item_append_text(item_param_pair, ", ID: %" PRIi64, *paramid);
                }
                bp_cbor_require_delete(paramid);
                bp_cbor_chunk_delete(chunk_paramid);

                const gint offset_value = offset;
                cbor_skip_next_item(tvb, &offset);
                if (dissect_media) {
                    tvbuff_t *tvb_value = tvb_new_subset_length(tvb, offset_value, offset - offset_value);
                    dissector_try_string(
                        dissect_media,
                        "application/cbor",
                        tvb_value,
                        pinfo,
                        tree_param_pair,
                        NULL
                    );
                }

                proto_item_set_len(item_param_pair, offset - offset_param_pair);
                bp_cbor_chunk_delete(chunk_param_pair);
            }

            proto_item_set_len(item_param_list, offset - offset_param_list);
            bp_cbor_chunk_delete(chunk_param_list);
        }
    }

    const gint offset_result_all_list = offset;
    bp_cbor_chunk_t *chunk_result_all_list = cbor_require_array(tvb, pinfo, tree_asb, &offset);
    if (chunk_result_all_list) {
        proto_item *item_result_all_list = proto_tree_add_int64(tree_asb, hf_asb_result_all_list, tvb, offset_result_all_list, 0, chunk_result_all_list->head_value);
        proto_tree *tree_result_all_list = proto_item_add_subtree(item_result_all_list, ett_result_all_list);

        // array sizes should agree
        cbor_require_array_size(tvb, pinfo, item_result_all_list, chunk_result_all_list, targets->len, targets->len);

        // iterate each target's results
        for (gint64 tgt_ix = 0; tgt_ix < chunk_result_all_list->head_value; ++tgt_ix) {
            const gint offset_result_tgt_list = offset;
            bp_cbor_chunk_t *chunk_result_tgt_list = cbor_require_array(tvb, pinfo, tree_asb, &offset);
            if (chunk_result_tgt_list) {
                proto_item *item_result_tgt_list = proto_tree_add_int64(tree_result_all_list, hf_asb_result_tgt_list, tvb, offset_result_tgt_list, 0, chunk_result_tgt_list->head_value);
                proto_tree *tree_result_tgt_list = proto_item_add_subtree(item_result_tgt_list, ett_result_tgt_list);

                // Hint at the associated target number
                if (tgt_ix < targets->len) {
                    const guint64 tgt_blknum = g_array_index(targets, guint64, tgt_ix);
                    proto_item *item_tgt_blknum = proto_tree_add_uint64(tree_result_tgt_list, hf_asb_target, tvb, 0, 0, tgt_blknum);
                    PROTO_ITEM_SET_GENERATED(item_tgt_blknum);
                }

                // iterate all results for this target
                for (gint64 tgt_ix = 0; tgt_ix < chunk_result_tgt_list->head_value; ++tgt_ix) {
                    const gint offset_result_pair = offset;
                    bp_cbor_chunk_t *chunk_result_pair = cbor_require_array_with_size(tvb, pinfo, tree_asb, &offset, 2, 2);
                    if (chunk_result_pair) {
                        proto_item *item_result_pair = proto_tree_add_item(tree_result_tgt_list, hf_asb_result_pair, tvb, offset_result_pair, 0, ENC_NA);
                        proto_tree *tree_result_pair = proto_item_add_subtree(item_result_pair, ett_result_pair);

                        bp_cbor_chunk_t *chunk_resultid = bp_scan_cbor_chunk(tvb, offset);
                        gint64 *resultid = cbor_require_int64(chunk_resultid);
                        proto_tree_add_cbor_int64(tree_result_pair, hf_asb_result_id, pinfo, tvb, chunk_resultid, resultid);
                        offset += chunk_resultid->data_length;
                        if (resultid) {
                            proto_item_append_text(item_result_pair, ", ID: %" PRIi64, *resultid);
                        }
                        bp_cbor_require_delete(resultid);
                        bp_cbor_chunk_delete(chunk_resultid);

                        const gint offset_value = offset;
                        cbor_skip_next_item(tvb, &offset);
                        if (dissect_media) {
                            tvbuff_t *tvb_value = tvb_new_subset_length(tvb, offset_value, offset - offset_value);
                            dissector_try_string(
                                    dissect_media,
                                    "application/cbor",
                                    tvb_value,
                                    pinfo,
                                    tree_result_pair,
                                    NULL
                            );
                        }

                        proto_item_set_len(item_result_pair, offset - offset_result_pair);
                        bp_cbor_chunk_delete(chunk_result_pair);
                    }
                }

                proto_item_set_len(item_result_tgt_list, offset - offset_result_tgt_list);
                bp_cbor_chunk_delete(chunk_result_tgt_list);
            }
        }

        proto_item_set_len(item_result_all_list, offset - offset_result_all_list);
        bp_cbor_chunk_delete(chunk_result_all_list);
    }

    g_array_free(targets, TRUE);
    bp_cbor_require_delete(flags);

    proto_item_set_len(item_asb, offset);
    bp_cbor_chunk_delete(chunk_asb);
    return offset;
}

/** Dissector for Bundle Integrity block.
 */
static int dissect_block_bib(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return dissect_block_asb(tvb, pinfo, tree, (bp_dissector_data_t *)data, hf_bib);
}

/** Dissector for Bundle Confidentiality block.
 */
static int dissect_block_bcb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return dissect_block_asb(tvb, pinfo, tree, (bp_dissector_data_t *)data, hf_bcb);
}

/// Re-initialize after a configuration change
static void reinit_bpsec(void) {
}

/// Overall registration of the protocol
static void proto_register_bpsec(void) {
    proto_bpsec = proto_register_protocol(
        "DTN Bundle Protocol Security", /* name */
        "BPSec", /* short name */
        "bpsec" /* abbrev */
    );

    proto_register_field_array(proto_bpsec, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_bpsec);
    expert_register_field_array(expert, expertitems, array_length(expertitems));

    prefs_register_protocol(proto_bpsec, reinit_bpsec);
}

static void proto_reg_handoff_bpsec(void) {
    dissect_media = find_dissector_table("media_type");

    /* Packaged extensions */
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_block_bib, proto_bpsec);
        dissector_add_uint("bpv7.block_type", 99, hdl); //FIXME: placeholder block type ID
    }
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_block_bcb, proto_bpsec);
        dissector_add_uint("bpv7.block_type", 98, hdl); //FIXME: placeholder block type ID
    }

    reinit_bpsec();
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
    plugin_bp.register_protoinfo = proto_register_bpsec;
    plugin_bp.register_handoff = proto_reg_handoff_bpsec;
    proto_register_plugin(&plugin_bp);
}
