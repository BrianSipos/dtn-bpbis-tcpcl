#include "packet-tcpclv4.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/tvbuff-int.h>
#include <epan/dissectors/packet-tcp.h>
#include <stdio.h>
#include <inttypes.h>

#if WIRESHARK_APIVERS >= 3
#include <ws_version.h>
#include <epan/dissectors/packet-tls.h>
#include <epan/dissectors/packet-tls-utils.h>
#define TLS_DISSECTOR_NAME "tls"
#else
#include <config.h>
#include <epan/dissectors/packet-ssl.h>
#include <epan/dissectors/packet-ssl-utils.h>
#define TLS_DISSECTOR_NAME "ssl"
#define WIRESHARK_VERSION_MAJOR VERSION_MAJOR
#define WIRESHARK_VERSION_MINOR VERSION_MINOR
#endif

/// Glib logging "domain" name
static const char *LOG_DOMAIN = "tcpclv4";

/// Protocol preferences and defaults
static const guint TCPCL_PORT_NUM = 4556;
static gboolean tcpcl_desegment_transfer = TRUE;
static gboolean tcpcl_analyze_sequence = TRUE;
static gboolean tcpcl_decode_bundle = TRUE;

/// Protocol handles
static int proto_tcpcl = -1;

/// Dissector handles
static dissector_handle_t handle_tcpcl = NULL;
static dissector_handle_t handle_ssl = NULL;
static dissector_handle_t handle_bp = NULL;

/// Dissect opaque CBOR parameters/results
static dissector_table_t dissect_media = NULL;
/// Extension sub-dissectors
static dissector_table_t sess_ext_dissectors;
static dissector_table_t xfer_ext_dissectors;

/// Transfer reassembly
static reassembly_table tcpcl_reassembly_table;

static const value_string message_type_vals[]={
    {TCPCL_MSGTYPE_SESS_INIT, "SESS_INIT"},
    {TCPCL_MSGTYPE_SESS_TERM, "SESS_TERM"},
    {TCPCL_MSGTYPE_MSG_REJECT, "MSG_REJECT"},
    {TCPCL_MSGTYPE_KEEPALIVE, "KEEPALIVE"},
    {TCPCL_MSGTYPE_XFER_SEGMENT, "XFER_SEGMENT"},
    {TCPCL_MSGTYPE_XFER_ACK, "XFER_ACK"},
    {TCPCL_MSGTYPE_XFER_REFUSE, "XFER_REFUSE"},
    {0, NULL},
};

static const value_string sessext_type_vals[]={
    {0, NULL},
};

static const value_string xferext_type_vals[]={
    {TCPCL_XFEREXT_TRANSFER_LEN, "Transfer Length"},
    {0, NULL},
};

static const value_string sess_term_reason_vals[]={
    {0x00, "Unknown"},
    {0x01, "Idle timeout"},
    {0x02, "Version mismatch"},
    {0x03, "Busy"},
    {0x04, "Contact Failure"},
    {0x05, "Resource Exhaustion"},
    {0, NULL},
};

static const value_string xfer_refuse_reason_vals[]={
    {0x00, "Unknown"},
    {0x01, "Completed"},
    {0x02, "No Resources"},
    {0x03, "Retransmit"},
    {0x04, "Not Acceptable"},
    {0x05, "Extension Failure"},
    {0, NULL},
};

static const value_string msg_reject_reason_vals[]={
    {0x00, "reserved"},
    {0x01, "Message Type Unknown"},
    {0x02, "Message Unsupported"},
    {0x03, "Message Unexpected"},
    {0, NULL},
};

static int hf_tcpcl = -1;
static int hf_chdr_tree = -1;
static int hf_chdr_magic = -1;
static int hf_chdr_version = -1;
static int hf_chdr_flags = -1;
static int hf_chdr_flags_cantls = -1;

static int hf_chdr_related = -1;
static int hf_negotiate_use_tls = -1;

static int hf_mhdr_tree = -1;
static int hf_mhdr_type = -1;
static int hf_sess_init_keepalive = -1;
static int hf_sess_init_seg_mru = -1;
static int hf_sess_init_xfer_mru = -1;
static int hf_sess_init_nodeid_len = -1;
static int hf_sess_init_nodeid_data = -1;
static int hf_sess_init_extlist_len = -1;
static int hf_sess_init_related = -1;
static int hf_negotiate_keepalive = -1;

static int hf_sess_term_flags = -1;
static int hf_sess_term_flags_reply = -1;
static int hf_sess_term_reason = -1;
static int hf_sess_term_related = -1;

static int hf_sessext_tree = -1;
static int hf_sessext_flags = -1;
static int hf_sessext_flags_crit = -1;
static int hf_sessext_type = -1;
static int hf_sessext_len = -1;
static int hf_sessext_data = -1;

static int hf_xferext_tree = -1;
static int hf_xferext_flags = -1;
static int hf_xferext_flags_crit = -1;
static int hf_xferext_type = -1;
static int hf_xferext_len = -1;
static int hf_xferext_data = -1;

static int hf_xfer_flags = -1;
static int hf_xfer_flags_start = -1;
static int hf_xfer_flags_end = -1;
static int hf_xfer_id = -1;
static int hf_xfer_total_len = -1;
static int hf_xfer_segment_extlist_len = -1;
static int hf_xfer_segment_data_len = -1;
static int hf_xfer_segment_seen_len = -1;
static int hf_xfer_segment_related_start = -1;
static int hf_xfer_segment_time_start = -1;
static int hf_xfer_segment_related_ack = -1;
static int hf_xfer_segment_time_diff = -1;
static int hf_xfer_ack_ack_len = -1;
static int hf_xfer_ack_time_start = -1;
static int hf_xfer_ack_related_seg = -1;
static int hf_xfer_ack_time_diff = -1;
static int hf_xfer_refuse_reason = -1;
static int hf_xfer_refuse_related_seg = -1;
static int hf_msg_reject_reason = -1;
static int hf_msg_reject_head = -1;

static int hf_xferload_fragments = -1;
static int hf_xferload_fragment = -1;
static int hf_xferload_fragment_overlap = -1;
static int hf_xferload_fragment_overlap_conflicts = -1;
static int hf_xferload_fragment_multiple_tails = -1;
static int hf_xferload_fragment_too_long_fragment = -1;
static int hf_xferload_fragment_error = -1;
static int hf_xferload_fragment_count = -1;
static int hf_xferload_reassembled_in = -1;
static int hf_xferload_reassembled_length = -1;
static int hf_xferload_reassembled_data = -1;
static gint ett_xferload_fragment = -1;
static gint ett_xferload_fragments = -1;

static int hf_xferext_transferlen_total_len = -1;

/// Field definitions
static hf_register_info fields[] = {
    {&hf_tcpcl, {"TCP Convergence Layer Version 4", "tcpclv4", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_chdr_tree, {"TCPCLv4 Contact Header", "tcpclv4.chdr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_chdr_magic, {"Protocol Magic", "tcpclv4.chdr.magic", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_chdr_version, {"Protocol Version", "tcpclv4.chdr.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_chdr_flags, {"Contact Flags", "tcpclv4.chdr.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_chdr_flags_cantls, {"CAN_TLS", "tcpclv4.chdr.can_tls", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL}},
    // Contact negotiation results
    {&hf_chdr_related, {"Related Header", "tcpclv4.chdr.related", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_negotiate_use_tls, {"Negotiated Use TLS", "tcpclv4.negotiated.use_tls", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_mhdr_tree, {"TCPCLv4 Message", "tcpclv4.mhdr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_mhdr_type, {"Message Type", "tcpclv4.mhdr.type", FT_UINT8, BASE_HEX, VALS(message_type_vals), 0x0, NULL, HFILL}},

    // Session extension fields
    {&hf_sessext_tree, {"Session Extension Item", "tcpclv4.sessext", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_sessext_flags, {"Item Flags", "tcpclv4.sessext.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_sessext_flags_crit, {"CRITICAL", "tcpclv4.sessext.flags.critical", FT_UINT8, BASE_DEC, NULL, TCPCL_EXTENSION_FLAG_CRITICAL, NULL, HFILL}},
    {&hf_sessext_type, {"Item Type", "tcpclv4.sessext.type", FT_UINT8, BASE_HEX, VALS(sessext_type_vals), 0x0, NULL, HFILL}},
    {&hf_sessext_len, {"Item Length", "tcpclv4.sessext.len", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_sessext_data, {"Type-Specific Data", "tcpclv4.sessext.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    // Transfer extension fields
    {&hf_xferext_tree, {"Transfer Extension Item", "tcpclv4.xferext", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_xferext_flags, {"Item Flags", "tcpclv4.xferext.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_xferext_flags_crit, {"CRITICAL", "tcpclv4.xferext.flags.critical", FT_UINT8, BASE_DEC, NULL, TCPCL_EXTENSION_FLAG_CRITICAL, NULL, HFILL}},
    {&hf_xferext_type, {"Item Type", "tcpclv4.xferext.type", FT_UINT8, BASE_HEX, VALS(xferext_type_vals), 0x0, NULL, HFILL}},
    {&hf_xferext_len, {"Item Length", "tcpclv4.xferext.len", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_xferext_data, {"Type-Specific Data", "tcpclv4.xferext.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    // SESS_INIT fields
    {&hf_sess_init_keepalive, {"Keepalive Interval", "tcpclv4.sess_init.keepalive", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL}},
    {&hf_sess_init_seg_mru, {"Segment MRU", "tcpclv4.sess_init.seg_mru", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_sess_init_xfer_mru, {"Transfer MRU", "tcpclv4.sess_init.xfer_mru", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_sess_init_nodeid_len, {"Node ID Length", "tcpclv4.sess_init.nodeid_len", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_sess_init_nodeid_data, {"Node ID Data (UTF8)", "tcpclv4.sess_init.nodeid_data", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL}},
    {&hf_sess_init_extlist_len, {"Extension Items Length", "tcpclv4.sess_init.extlist_len", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_sess_init_related, {"Related SESS_INIT", "tcpclv4.sess_init.related", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    // Session negotiation results
    {&hf_negotiate_keepalive, {"Negotiated Keepalive Interval", "tcpclv4.negotiated.keepalive", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL}},
    // SESS_TERM fields
    {&hf_sess_term_flags, {"Flags", "tcpclv4.sess_term.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_sess_term_flags_reply, {"REPLY", "tcpclv4.sess_term.flags.reply", FT_UINT8, BASE_DEC, NULL, TCPCL_SESS_TERM_FLAG_REPLY, NULL, HFILL}},
    {&hf_sess_term_reason, {"Reason", "tcpclv4.ses_term.reason", FT_UINT8, BASE_DEC, VALS(sess_term_reason_vals), 0x0, NULL, HFILL}},
    {&hf_sess_term_related, {"Related SESS_TERM", "tcpclv4.ses_term.related", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    // Common transfer fields
    {&hf_xfer_flags, {"Transfer Flags", "tcpclv4.xfer_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_flags_start, {"START", "tcpclv4.xfer_flags.start", FT_UINT8, BASE_DEC, NULL, TCPCL_TRANSFER_FLAG_START, NULL, HFILL}},
    {&hf_xfer_flags_end, {"END", "tcpclv4.xfer_flags.end", FT_UINT8, BASE_DEC, NULL, TCPCL_TRANSFER_FLAG_END, NULL, HFILL}},
    {&hf_xfer_id, {"Transfer ID", "tcpclv4.xfer_id", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_total_len, {"Expected Total Length", "tcpclv4.xfer.total_len", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    // XFER_SEGMENT fields
    {&hf_xfer_segment_extlist_len, {"Extension Items Length", "tcpclv4.xfer_segment.extlist_len", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_xfer_segment_data_len, {"Segment Length", "tcpclv4.xfer_segment.data_len", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_xfer_segment_seen_len, {"Seen Length", "tcpclv4.xfer_segment.seen_len", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_xfer_segment_related_start, {"Related XFER_SEGMENT start", "tcpclv4.xfer_segment.related_start", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_segment_time_start, {"Time since transfer Start", "tcpclv4.xfer_segment.time_since_start", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_segment_related_ack, {"Related XFER_ACK", "tcpclv4.xfer_segment.related_ack", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_segment_time_diff, {"Acknowledgment Time", "tcpclv4.xfer_segment.time_diff", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    // XFER_ACK fields
    {&hf_xfer_ack_ack_len, {"Acknowledged Length", "tcpclv4.xfer_ack.ack_len", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_xfer_ack_time_start, {"Time since transfer Start", "tcpclv4.xfer_segment.time_since_start", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_ack_related_seg, {"Related XFER_SEGMENT", "tcpclv4.xfer_ack.related_seg", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_ack_time_diff, {"Acknowledgment Time", "tcpclv4.xfer_ack.time_diff", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    // XFER_REFUSE fields
    {&hf_xfer_refuse_reason, {"Reason", "tcpclv4.xfer_refuse.reason", FT_UINT8, BASE_DEC, VALS(xfer_refuse_reason_vals), 0x0, NULL, HFILL}},
    {&hf_xfer_refuse_related_seg, {"Related XFER_SEGMENT", "tcpclv4.xfer_refuse.related_seg", FT_FRAMENUM, BASE_NONE, VALS(xfer_refuse_reason_vals), 0x0, NULL, HFILL}},
    // MSG_REJECT fields
    {&hf_msg_reject_reason, {"Reason", "tcpclv4.msg_reject.reason", FT_UINT8, BASE_DEC, VALS(msg_reject_reason_vals), 0x0, NULL, HFILL}},
    {&hf_msg_reject_head, {"Rejected Type", "tcpclv4.msg_reject.head", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

    {&hf_xferload_fragments,
        {"Transfer fragments", "tcpclv4.xferload.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment,
        {"Transfer fragment", "tcpclv4.xferload.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment_overlap,
        {"Transfer fragment overlap", "tcpclv4.xferload.fragment.overlap",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment_overlap_conflicts,
        {"Transfer fragment overlapping with conflicting data",
        "tcpclv4.xferload.fragment.overlap.conflicts",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment_multiple_tails,
        {"Message has multiple tail fragments",
        "tcpclv4.xferload.fragment.multiple_tails",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment_too_long_fragment,
        {"Transfer fragment too long", "tcpclv4.xferload.fragment.too_long_fragment",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment_error,
        {"Message defragmentation error", "tcpclv4.xferload.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment_count,
        {"Transfer fragment count", "tcpclv4.xferload.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_reassembled_in,
        {"Reassembled in", "tcpclv4.xferload.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_reassembled_length,
        {"Reassembled length", "tcpclv4.xferload.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_reassembled_data,
        {"Reassembled data", "tcpclv4.xferload.reassembled.data",
        FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

    // Specific extensions
    {&hf_xferext_transferlen_total_len, {"Total Length", "tcpclv4.xferext.transfer_length.total_len", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
};
static const int *chdr_flags[] = {
    &hf_chdr_flags_cantls,
    NULL
};
static const int *sess_term_flags[] = {
    &hf_sess_term_flags_reply,
    NULL
};
static const int *xfer_flags[] = {
    &hf_xfer_flags_start,
    &hf_xfer_flags_end,
    NULL
};
static const int *sessext_flags[] = {
    &hf_sessext_flags_crit,
    NULL
};
static const int *xferext_flags[] = {
    &hf_xferext_flags_crit,
    NULL
};
static const fragment_items xferload_frag_items = {
    /* Fragment subtrees */
    &ett_xferload_fragment,
    &ett_xferload_fragments,
    /* Fragment fields */
    &hf_xferload_fragments,
    &hf_xferload_fragment,
    &hf_xferload_fragment_overlap,
    &hf_xferload_fragment_overlap_conflicts,
    &hf_xferload_fragment_multiple_tails,
    &hf_xferload_fragment_too_long_fragment,
    &hf_xferload_fragment_error,
    &hf_xferload_fragment_count,
    /* Reassembled in field */
    &hf_xferload_reassembled_in,
    &hf_xferload_reassembled_length,
    &hf_xferload_reassembled_data,
    /* Tag */
    "Transfer fragments"
};

static int ett_tcpcl = -1;
static int ett_chdr = -1;
static int ett_chdr_flags = -1;
static int ett_chdr_badmagic = -1;
static int ett_mhdr = -1;
static int ett_sess_term_flags = -1;
static int ett_xfer_flags = -1;
static int ett_sessext = -1;
static int ett_sessext_flags = -1;
static int ett_sessext_data = -1;
static int ett_xferext = -1;
static int ett_xferext_flags = -1;
static int ett_xferext_data = -1;
/// Tree structures
static int *ett[] = {
    &ett_tcpcl,
    &ett_chdr,
    &ett_chdr_flags,
    &ett_chdr_badmagic,
    &ett_mhdr,
    &ett_sess_term_flags,
    &ett_xfer_flags,
    &ett_sessext,
    &ett_sessext_flags,
    &ett_sessext_data,
    &ett_xferext,
    &ett_xferext_flags,
    &ett_xferext_data,
    &ett_xferload_fragment,
    &ett_xferload_fragments,
};

static expert_field ei_invalid_magic = EI_INIT;
static expert_field ei_invalid_version = EI_INIT;
static expert_field ei_invalid_msg_type = EI_INIT;
static expert_field ei_invalid_sessext_type = EI_INIT;
static expert_field ei_invalid_xferext_type = EI_INIT;
static expert_field ei_extitem_critical = EI_INIT;
static expert_field ei_chdr_duplicate = EI_INIT;
static expert_field ei_sess_init_missing = EI_INIT;
static expert_field ei_sess_init_duplicate = EI_INIT;
static expert_field ei_sess_term_duplicate = EI_INIT;
static expert_field ei_sess_term_reply_flag = EI_INIT;
static expert_field ei_sess_term_reply_reason = EI_INIT;
static expert_field ei_xfer_seg_over_seg_mru = EI_INIT;
static expert_field ei_xfer_seg_missing_start = EI_INIT;
static expert_field ei_xfer_seg_duplicate_start = EI_INIT;
static expert_field ei_xfer_seg_missing_end = EI_INIT;
static expert_field ei_xfer_seg_duplicate_end = EI_INIT;
static expert_field ei_xfer_seg_no_relation = EI_INIT;
static expert_field ei_xfer_seg_large_xferid = EI_INIT;
static expert_field ei_xfer_seg_over_total_len = EI_INIT;
static expert_field ei_xfer_seg_mismatch_total_len = EI_INIT;
static expert_field ei_xfer_ack_mismatch_flags = EI_INIT;
static expert_field ei_xfer_ack_no_relation = EI_INIT;
static expert_field ei_xfer_refuse_no_transfer = EI_INIT;
static expert_field ei_xferload_over_xfer_mru = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_invalid_magic, { "tcpclv4.invalid_contact_magic", PI_PROTOCOL, PI_ERROR, "Magic string is invalid", EXPFILL}},
    {&ei_invalid_version, { "tcpclv4.invalid_contact_version", PI_PROTOCOL, PI_ERROR, "Protocol version mismatch", EXPFILL}},
    {&ei_invalid_msg_type, { "tcpclv4.unknown_message_type", PI_UNDECODED, PI_ERROR, "Message type is unknown", EXPFILL}},
    {&ei_invalid_sessext_type, { "tcpclv4.unknown_sessext_type", PI_UNDECODED, PI_WARN, "Session Extension type is unknown", EXPFILL}},
    {&ei_invalid_xferext_type, { "tcpclv4.unknown_xferext_type", PI_UNDECODED, PI_WARN, "Transfer Extension type is unknown", EXPFILL}},
    {&ei_extitem_critical, { "tcpclv4.extitem_critical", PI_REQUEST_CODE, PI_CHAT, "Extension Item is critical", EXPFILL}},
    {&ei_chdr_duplicate, { "tcpclv4.chdr_duplicate", PI_SEQUENCE, PI_ERROR, "Duplicate Contact Header", EXPFILL}},
    {&ei_sess_init_missing, { "tcpclv4.sess_init_missing", PI_SEQUENCE, PI_ERROR, "Expected SESS_INIT message first", EXPFILL}},
    {&ei_sess_init_duplicate, { "tcpclv4.sess_init_duplicate", PI_SEQUENCE, PI_ERROR, "Duplicate SESS_INIT message", EXPFILL}},
    {&ei_sess_term_duplicate, { "tcpclv4.sess_term_duplicate", PI_SEQUENCE, PI_ERROR, "Duplicate SESS_TERM message", EXPFILL}},
    {&ei_sess_term_reply_flag, { "tcpclv4.sess_term_reply_flag", PI_SEQUENCE, PI_ERROR, "Reply SESS_TERM missing flag", EXPFILL}},
    {&ei_sess_term_reply_reason, { "tcpclv4.sess_term_reply_reason", PI_SEQUENCE, PI_ERROR, "Reply SESS_TERM reason mismatch", EXPFILL}},
    {&ei_xfer_seg_over_seg_mru, { "tcpclv4.xfer_seg_over_seg_mru", PI_PROTOCOL, PI_WARN, "Segment data size larger than peer MRU", EXPFILL}},
    {&ei_xfer_seg_missing_start, { "tcpclv4.xfer_seg_missing_start", PI_SEQUENCE, PI_ERROR, "First XFER_SEGMENT is missing START flag", EXPFILL}},
    {&ei_xfer_seg_duplicate_start, { "tcpclv4.xfer_seg_duplicate_start", PI_SEQUENCE, PI_ERROR, "Non-first XFER_SEGMENT has START flag", EXPFILL}},
    {&ei_xfer_seg_missing_end, { "tcpclv4.xfer_seg_missing_end", PI_SEQUENCE, PI_ERROR, "Last XFER_SEGMENT is missing END flag", EXPFILL}},
    {&ei_xfer_seg_duplicate_end, { "tcpclv4.xfer_seg_duplicate_end", PI_SEQUENCE, PI_ERROR, "Non-last XFER_SEGMENT has END flag", EXPFILL}},
    {&ei_xfer_seg_no_relation, { "tcpclv4.xfer_seg_no_relation", PI_SEQUENCE, PI_NOTE, "XFER_SEGMENT has no related XFER_ACK", EXPFILL}},
    {&ei_xfer_seg_large_xferid, { "tcpclv4.xfer_seg_large_xferid", PI_REASSEMBLE, PI_NOTE, "XFER_SEGMENT has a transfer ID larger than Wireshark can handle", EXPFILL}},
    {&ei_xfer_seg_over_total_len, { "tcpclv4.xfer_seg_over_total_len", PI_SEQUENCE, PI_ERROR, "XFER_SEGMENT has accumulated length beyond the Transfer Length extension", EXPFILL}},
    {&ei_xfer_seg_mismatch_total_len, { "tcpclv4.xfer_seg_over_total_len", PI_SEQUENCE, PI_ERROR, "Transfer has total length different than the Transfer Length extension", EXPFILL}},
    {&ei_xfer_ack_mismatch_flags, { "tcpclv4.xfer_ack_mismatch_flags", PI_SEQUENCE, PI_ERROR, "XFER_ACK does not have flags matching XFER_SEGMENT", EXPFILL}},
    {&ei_xfer_ack_no_relation, { "tcpclv4.xfer_ack_no_relation", PI_SEQUENCE, PI_NOTE, "XFER_ACK has no related XFER_SEGMENT", EXPFILL}},
    {&ei_xfer_refuse_no_transfer, { "tcpclv4.xfer_refuse_no_transfer", PI_SEQUENCE, PI_NOTE, "XFER_REFUSE has no related XFER_SEGMENT(s)", EXPFILL}},
    {&ei_xferload_over_xfer_mru, { "tcpclv4.xferload_over_xfer_mru", PI_SEQUENCE, PI_NOTE, "Transfer larger than peer MRU", EXPFILL}},
};

/** Delete an arbitrary object allocated under this file scope.
 *
 * @param obj The object to delete.
 */
static void file_scope_delete(gpointer ptr) {
    wmem_free(wmem_file_scope(), ptr);
}

static guint64 * guint64_new(const guint64 val) {
    guint64 *obj = wmem_new(wmem_file_scope(), guint64);
    *obj = val;
    return obj;
}

#define guint64_delete file_scope_delete

void frame_loc_init(frame_loc_t *loc, const packet_info *pinfo, tvbuff_t *tvb, const gint offset) {
    loc->frame_num = pinfo->num;
    // This is a messy way to determine the index,
    // but no other public functions allow determining how two TVB are related
    loc->src_ix = -1;
    for(GSList *srcit = pinfo->data_src; srcit != NULL; srcit = g_slist_next(srcit)) {
        ++(loc->src_ix);
        struct data_source *src = srcit->data;
        if (get_data_source_tvb(src)->real_data == tvb->real_data) {
            break;
        }
    }
    loc->raw_offset = tvb_raw_offset(tvb) + offset;
}

frame_loc_t * frame_loc_new(const packet_info *pinfo, tvbuff_t *tvb, const gint offset) {
    frame_loc_t *obj = wmem_new(wmem_file_scope(), frame_loc_t);
    frame_loc_init(obj, pinfo, tvb, offset);
    return obj;
}

void frame_loc_delete(gpointer ptr) {
    file_scope_delete(ptr);
}

frame_loc_t * frame_loc_clone(const frame_loc_t *loc) {
    frame_loc_t *obj = wmem_new(wmem_file_scope(), frame_loc_t);
    *obj = *loc;
    return obj;
}

gboolean frame_loc_valid(const frame_loc_t *loc) {
    return (loc->raw_offset >= 0);
}

gint frame_loc_compare(gconstpointer a, gconstpointer b, gpointer user_data _U_) {
    const frame_loc_t *aloc = a;
    const frame_loc_t *bloc = b;

    if (aloc->frame_num < bloc->frame_num) {
        return -1;
    }
    else if (aloc->frame_num > bloc->frame_num) {
        return 1;
    }

    if (aloc->src_ix < bloc->src_ix) {
        return -1;
    }
    else if (aloc->src_ix > bloc->src_ix) {
        return 1;
    }

    if (aloc->raw_offset < bloc->raw_offset) {
        return -1;
    }
    else if (aloc->raw_offset > bloc->raw_offset) {
        return 1;
    }
    return 0;
}

gboolean frame_loc_equal(gconstpointer a, gconstpointer b) {
    const frame_loc_t *aobj = a;
    const frame_loc_t *bobj = b;
    return (
        (aobj->frame_num == bobj->frame_num)
        && (aobj->src_ix == bobj->src_ix)
        && (aobj->raw_offset == bobj->raw_offset)
    );
}

guint frame_loc_hash(gconstpointer key) {
    const frame_loc_t *obj = key;
    return (
        g_int_hash(&(obj->frame_num))
        ^ g_int64_hash(&(obj->raw_offset))
    );
}

struct ack_meta;
typedef struct ack_meta ack_meta_t;
struct seg_meta;
typedef struct seg_meta seg_meta_t;

struct seg_meta {
    /// Location associated with this metadata
    frame_loc_t frame_loc;
    /// Timestamp on the frame (end time if reassembled)
    nstime_t frame_time;
    /// Copy of message flags
    guint8 flags;
    /// Total transfer length including this segment
    guint64 seen_len;

    /// Potential related start segment
    seg_meta_t *related_start;
    /// Potential related XFER_ACK
    ack_meta_t *related_ack;
};

static seg_meta_t * seg_meta_new(const packet_info *pinfo, const frame_loc_t *loc) {
    seg_meta_t *obj = wmem_new(wmem_file_scope(), seg_meta_t);
    obj->frame_loc = *loc;
    obj->frame_time = pinfo->abs_ts;
    obj->flags = 0;
    obj->seen_len = 0;
    obj->related_start = NULL;
    obj->related_ack = NULL;
    return obj;
}

#define seg_meta_delete file_scope_delete

/** Function to match the GCompareDataFunc signature.
 */
static gint segment_compare_loc(gconstpointer a, gconstpointer b, gpointer user_data _U_) {
    return frame_loc_compare(
        &(((seg_meta_t *)a)->frame_loc),
        &(((seg_meta_t *)b)->frame_loc),
        NULL
    );
}

struct ack_meta {
    /// Location associated with this metadata
    frame_loc_t frame_loc;
    /// Timestamp on the frame (end time if reassembled)
    nstime_t frame_time;
    /// Copy of message flags
    guint8 flags;
    /// Total acknowledged length including this ack
    guint64 seen_len;

    /// Potential related start segment
    seg_meta_t *related_start;
    /// Potential related XFER_SEGMENT
    seg_meta_t *related_seg;
};

static ack_meta_t * ack_meta_new(const packet_info *pinfo, const frame_loc_t *loc) {
    ack_meta_t *obj = wmem_new(wmem_file_scope(), ack_meta_t);
    obj->frame_loc = *loc;
    obj->frame_time = pinfo->abs_ts;
    obj->flags = 0;
    obj->seen_len = 0;
    obj->related_start = NULL;
    obj->related_seg = NULL;
    return obj;
}

#define ack_meta_delete file_scope_delete

/** Function to match the GCompareDataFunc signature.
 */
static gint ack_compare_loc(gconstpointer a, gconstpointer b, gpointer user_data _U_) {
    return frame_loc_compare(
        &(((seg_meta_t *)a)->frame_loc),
        &(((seg_meta_t *)b)->frame_loc),
        NULL
    );
}

typedef struct {
    /// Ordered list of seg_meta_t for XFER_SEGMENT as seen in the first scan.
    /// This container owns the object allocations.
    GSequence *seg_list;

    /// Ordered list of ack_meta_t for XFER_ACK as seen in the first scan.
    /// This container owns the object allocations.
    GSequence *ack_list;

    /// Optional Transfer Length extension
    guint64 *total_length;
} tcpcl_transfer_t;

static tcpcl_transfer_t * tcpcl_transfer_new(void) {
    tcpcl_transfer_t *obj = wmem_new(wmem_file_scope(), tcpcl_transfer_t);
    obj->seg_list = g_sequence_new(seg_meta_delete);
    obj->ack_list = g_sequence_new(ack_meta_delete);
    obj->total_length = NULL;
    return obj;
}

static void tcpcl_transfer_delete(gpointer ptr) {
    tcpcl_transfer_t *obj = ptr;
    g_sequence_free(obj->seg_list);
    g_sequence_free(obj->ack_list);
    guint64_delete(obj->total_length);
    file_scope_delete(ptr);
}

static tcpcl_transfer_t * get_or_create_transfer_t(GHashTable *table, const guint64 xfer_id) {
    tcpcl_transfer_t *xfer = g_hash_table_lookup(table, &xfer_id);
    if (!xfer) {
        xfer = tcpcl_transfer_new();
        g_hash_table_insert(table, guint64_new(xfer_id), xfer);
    }
    return xfer;
}

typedef struct {
    /// Address for this peer
    address addr;
    /// Port for the this peer
    guint32 port;

    /// Frame number in which the contact header starts
    frame_loc_t chdr_seen;
    /// CAN_TLS flag from the contact header
    gboolean can_tls;

    /// Frame number in which the SESS_INIT message starts
    frame_loc_t sess_init_seen;
    /// Keepalive duration (s) from SESS_INIT
    guint16 keepalive;
    /// Segment MRU
    guint64 segment_mru;
    /// Transfer MRU
    guint64 transfer_mru;

    /// Frame number in which the SESS_TERM message starts
    frame_loc_t sess_term_seen;
    /// SESS_TERM reason
    guint8 sess_term_reason;

    /// Map of frame_loc_t to possible associated transfer ID
    GHashTable *frame_loc_to_transfer;

    /// Table of tcpcl_transfer_t pointers for transfer IDs sent from this peer
    GHashTable *transfers;
} tcpcl_peer_t;

static tcpcl_peer_t * tcpcl_peer_new(void) {
    tcpcl_peer_t *obj = wmem_new(wmem_file_scope(), tcpcl_peer_t);
    *obj = (tcpcl_peer_t){ADDRESS_INIT_NONE, 0, FRAME_LOC_INIT, FALSE, FRAME_LOC_INIT, 0, 0, 0, FRAME_LOC_INIT, 0, NULL, NULL};
    obj->frame_loc_to_transfer = g_hash_table_new_full(frame_loc_hash, frame_loc_equal, frame_loc_delete, guint64_delete);
    obj->transfers = g_hash_table_new_full(g_int64_hash, g_int64_equal, guint64_delete, tcpcl_transfer_delete);
    return obj;
}

#if 0
static void tcpcl_peer_delete(gpointer ptr) {
    tcpcl_peer_t *obj = ptr;
    g_hash_table_destroy(obj->frame_loc_to_transfer);
    g_hash_table_destroy(obj->transfers);
    file_scope_delete(ptr);
}
#endif

static void tcpcl_peer_associate_transfer(tcpcl_peer_t *peer, const frame_loc_t *loc, const guint64 xfer_id) {
    frame_loc_t *key = frame_loc_clone(loc);
    gpointer *xfer = g_hash_table_lookup(peer->frame_loc_to_transfer, key);
    if (!xfer) {
        g_hash_table_insert(peer->frame_loc_to_transfer, key, guint64_new(xfer_id));
    }
    frame_loc_delete(key);
}

typedef struct {
    /// Information for the active side of the session
    tcpcl_peer_t *active;
    /// Information for the passive side of the session
    tcpcl_peer_t *passive;

    /// True when contact negotiation is finished
    gboolean contact_negotiated;
    /// Negotiated use of TLS from @c can_tls of the peers
    gboolean session_use_tls;
    /// The last frame before TLS handshake
    frame_loc_t session_tls_start;

    /// True when session negotiation is finished
    gboolean sess_negotiated;
    /// Negotiated session keepalive
    guint16 sess_keepalive;
} tcpcl_conversation_t;

static tcpcl_conversation_t * tcpcl_conversation_new() {
    tcpcl_conversation_t *obj = wmem_new(wmem_file_scope(), tcpcl_conversation_t);
    *obj = (tcpcl_conversation_t){NULL, NULL, FALSE, FALSE, FRAME_LOC_INIT, FALSE, 0};
    obj->active = tcpcl_peer_new();
    obj->passive = tcpcl_peer_new();
    return obj;
}

/** Get the peers associated with the sender and receiver of the frame.
 *
 * @param[out] tx_peer The peer sending the frame.
 * @param[out] rx_peer The peer sending the frame.
 * @param tcpcl_convo The conversation context.
 * @param pinfo Packet info for the frame.
 */
static void get_peers(tcpcl_peer_t **tx_peer, tcpcl_peer_t **rx_peer, const tcpcl_conversation_t *tcpcl_convo, const packet_info *pinfo) {
    const gboolean src_is_active = (
        addresses_equal(&(tcpcl_convo->active->addr), &(pinfo->src))
        && (tcpcl_convo->active->port == pinfo->srcport)
    );
    if (src_is_active) {
        *tx_peer = tcpcl_convo->active;
        *rx_peer = tcpcl_convo->passive;
    }
    else {
        *tx_peer = tcpcl_convo->passive;
        *rx_peer = tcpcl_convo->active;
    }
}

static void try_negotiate(tcpcl_conversation_t *tcpcl_convo, packet_info *pinfo, const frame_loc_t *loc) {
    if (!(tcpcl_convo->contact_negotiated)
        && frame_loc_valid(&(tcpcl_convo->active->chdr_seen))
        && frame_loc_valid(&(tcpcl_convo->passive->chdr_seen))) {
        tcpcl_convo->session_use_tls = (
            tcpcl_convo->active->can_tls & tcpcl_convo->passive->can_tls
        );
        tcpcl_convo->contact_negotiated = TRUE;

        if (tcpcl_convo->session_use_tls
            && (!frame_loc_valid(&(tcpcl_convo->session_tls_start)))) {
            col_append_str(pinfo->cinfo, COL_INFO, " [STARTTLS]");
            tcpcl_convo->session_tls_start = *loc;
            ssl_starttls_ack(handle_ssl, pinfo, handle_tcpcl);
        }
    }

    if (!(tcpcl_convo->sess_negotiated)
        && frame_loc_valid(&(tcpcl_convo->active->sess_init_seen))
        && frame_loc_valid(&(tcpcl_convo->passive->sess_init_seen))) {
        tcpcl_convo->sess_keepalive = MIN(
            tcpcl_convo->active->keepalive,
            tcpcl_convo->passive->keepalive
        );
        tcpcl_convo->sess_negotiated = TRUE;

    }
}

static guint get_message_len(packet_info *pinfo, tvbuff_t *tvb, int ext_offset, void *data _U_) {
    conversation_t *convo = find_or_create_conversation(pinfo);
    tcpcl_conversation_t *tcpcl_convo = (tcpcl_conversation_t *)conversation_get_proto_data(convo, proto_tcpcl);
    if (!tcpcl_convo) {
        return 0;
    }
    const guint buflen = tvb_captured_length(tvb);
    const guint init_offset = ext_offset;
    guint offset = ext_offset;

    frame_loc_t *cur_loc = frame_loc_new(pinfo, tvb, offset);
    tcpcl_peer_t *tx_peer, *rx_peer;
    get_peers(&tx_peer, &rx_peer, tcpcl_convo, pinfo);
    guint8 msgtype = 0;
    g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "get_message_len() scanning at %d|%d|%d ...\n", cur_loc->frame_num, cur_loc->src_ix, cur_loc->raw_offset);
    const gboolean is_contact = (
        !frame_loc_valid(&(tx_peer->chdr_seen))
        || frame_loc_equal(&(tx_peer->chdr_seen), cur_loc)
    );
    if (is_contact) {
        offset += 6;
    }
    else {
        msgtype = tvb_get_guint8(tvb, offset);
        offset += 1;

        switch(msgtype) {
            case TCPCL_MSGTYPE_SESS_INIT: {
                offset += 2 + 8 + 8;
                if (buflen < offset + 2) {
                    return 0;
                }
                guint16 nodeid_len = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
                offset += 2;
                offset += nodeid_len;
                if (buflen < offset + 4) {
                    return 0;
                }
                guint32 extlist_len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                offset += 4;
                offset += extlist_len;
                break;
            }
            case TCPCL_MSGTYPE_SESS_TERM: {
                offset += 1 + 1;
                break;
            }
            case TCPCL_MSGTYPE_XFER_SEGMENT: {
                if (buflen < offset + 1) {
                    return 0;
                }
                guint8 flags = tvb_get_guint8(tvb, offset);
                offset += 1;
                offset += 8;
                if (flags & TCPCL_TRANSFER_FLAG_START) {
                    if (buflen < offset + 4) {
                        return 0;
                    }
                    guint32 extlist_len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                    offset += 4;
                    offset += extlist_len;
                }
                if (buflen < offset + 8) {
                    return 0;
                }
                guint64 payload_len = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                offset += 8;
                offset += payload_len;
                break;
            }
            case TCPCL_MSGTYPE_XFER_ACK: {
                offset += 1 + 8 + 8;
                break;
            }
            case TCPCL_MSGTYPE_XFER_REFUSE: {
                offset += 1 + 8;
                break;
            }
            case TCPCL_MSGTYPE_KEEPALIVE: {
                break;
            }
            case TCPCL_MSGTYPE_MSG_REJECT: {
                offset += 1 + 1;
                break;
            }
            default:
                break;
        }
    }
    const int needlen = offset - init_offset;
    g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "get_message_len() decoded msg type %x, remain length %d, need length %d\n", msgtype, buflen - init_offset, needlen);
    frame_loc_delete(cur_loc);
    return needlen;
}

static gint dissect_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    conversation_t *convo = find_or_create_conversation(pinfo);
    tcpcl_conversation_t *tcpcl_convo = (tcpcl_conversation_t *)conversation_get_proto_data(convo, proto_tcpcl);
    if (!tcpcl_convo) {
        return 0;
    }
    gint offset = 0;
    // Length of non-protocol 'payload' data in this message
    gint payload_len = 0;

    frame_loc_t *cur_loc = frame_loc_new(pinfo, tvb, 0);
    tcpcl_peer_t *tx_peer, *rx_peer;
    get_peers(&tx_peer, &rx_peer, tcpcl_convo, pinfo);

    guint8 msgtype = 0;
    const char *msgtype_name = NULL;
    proto_tree *tree_msg = NULL;
    tvbuff_t *xferload_tvb = NULL;
    g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "dissect_message() scanning at %d|%d|%d ...\n", cur_loc->frame_num, cur_loc->src_ix, cur_loc->raw_offset);
    const gboolean is_contact = (
        !frame_loc_valid(&(tx_peer->chdr_seen))
        || frame_loc_equal(&(tx_peer->chdr_seen), cur_loc)
    );
    if (is_contact) {
        msgtype_name = "Contact Header";
        g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "dissect_message() decoding contact header, buf length %d\n", tvb_captured_length(tvb));

        proto_item *item_chdr = proto_tree_add_item(tree, hf_chdr_tree, tvb, offset, 0, ENC_NA);
        tree_msg = proto_item_add_subtree(item_chdr, ett_chdr);

        const void *magic_data = tvb_memdup(wmem_packet_scope(), tvb, offset, 4);
        proto_item *item_magic = proto_tree_add_bytes(tree_msg, hf_chdr_magic, tvb, offset, 4, magic_data);
        offset += 4;
        if (strncmp((const char *)magic_data, "dtn!", 4) != 0) {
            expert_add_info(pinfo, item_magic, &ei_invalid_magic);
        }

        guint8 version = tvb_get_guint8(tvb, offset);
        proto_item *item_version = proto_tree_add_uint(tree_msg, hf_chdr_version, tvb, offset, 1, version);
        offset += 1;
        if (version != 4) {
            expert_add_info(pinfo, item_version, &ei_invalid_version);
        }

        guint8 flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_bitmask(tree_msg, tvb, offset, hf_chdr_flags, ett_chdr_flags, chdr_flags, ENC_BIG_ENDIAN);
        offset += 1;

        proto_item_set_len(item_chdr, offset);

        if (frame_loc_valid(&(tx_peer->chdr_seen))) {
            if (tcpcl_analyze_sequence) {
                if (!frame_loc_equal(&(tx_peer->chdr_seen), cur_loc)) {
                    expert_add_info(pinfo, item_chdr, &ei_chdr_duplicate);
                }
            }
        }
        else {
            tx_peer->chdr_seen = *cur_loc;
            tx_peer->can_tls = (flags & TCPCL_CONTACT_FLAG_CANTLS);
        }
    }
    else {
        proto_item *item_msg = proto_tree_add_item(tree, hf_mhdr_tree, tvb, offset, 0, ENC_NA);
        tree_msg = proto_item_add_subtree(item_msg, ett_mhdr);

        msgtype = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree_msg, hf_mhdr_type, tvb, offset, 1, msgtype);
        offset += 1;
        g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "dissect_message() decoding msg type %x, buf length %d\n", msgtype, tvb_captured_length(tvb));
        msgtype_name = val_to_str(msgtype, message_type_vals, "type 0x%" PRIx32);

        wmem_strbuf_t *suffix_text = wmem_strbuf_new(wmem_packet_scope(), NULL);
        switch(msgtype) {
            case TCPCL_MSGTYPE_SESS_INIT: {
                guint16 keepalive = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint(tree_msg, hf_sess_init_keepalive, tvb, offset, 2, keepalive);
                offset += 2;

                guint64 seg_mru = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint64(tree_msg, hf_sess_init_seg_mru, tvb, offset, 8, seg_mru);
                offset += 8;

                guint64 xfer_mru = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint64(tree_msg, hf_sess_init_xfer_mru, tvb, offset, 8, xfer_mru);
                offset += 8;

                guint16 nodeid_len = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint(tree_msg, hf_sess_init_nodeid_len, tvb, offset, 2, nodeid_len);
                offset += 2;

                {
                    guint8 *nodeid_data = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, nodeid_len, ENC_UTF_8);
                    proto_tree_add_string(tree_msg, hf_sess_init_nodeid_data, tvb, offset, nodeid_len, (const char *)nodeid_data);
                    wmem_free(wmem_packet_scope(), nodeid_data);
                }
                offset += nodeid_len;

                guint32 extlist_len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint(tree_msg, hf_sess_init_extlist_len, tvb, offset, 4, extlist_len);
                offset += 4;

                gint extlist_offset = 0;
                while (extlist_offset < (int)extlist_len) {
                    gint extitem_offset = 0;
                    proto_item *item_ext = proto_tree_add_item(tree_msg, hf_sessext_tree, tvb, offset + extlist_offset, 0, ENC_NA);
                    proto_tree *tree_ext = proto_item_add_subtree(item_ext, ett_sessext);

                    guint8 extitem_flags = tvb_get_guint8(tvb, offset + extlist_offset + extitem_offset);
                    proto_tree_add_bitmask(tree_ext, tvb, offset + extlist_offset + extitem_offset, hf_sessext_flags, ett_sessext_flags, sessext_flags, ENC_BIG_ENDIAN);
                    extitem_offset += 1;
                    const gboolean is_critical = (extitem_flags & TCPCL_EXTENSION_FLAG_CRITICAL);
                    if (is_critical) {
                        expert_add_info(pinfo, item_ext, &ei_extitem_critical);
                    }

                    guint32 extitem_type = tvb_get_guint16(tvb, offset + extlist_offset + extitem_offset, ENC_BIG_ENDIAN);
                    proto_item *item_type = proto_tree_add_uint(tree_ext, hf_sessext_type, tvb, offset + extlist_offset + extitem_offset, 2, extitem_type);
                    extitem_offset += 2;

                    guint32 extitem_len = tvb_get_guint16(tvb, offset + extlist_offset + extitem_offset, ENC_BIG_ENDIAN);
                    proto_tree_add_uint(tree_ext, hf_sessext_len, tvb, offset + extlist_offset + extitem_offset, 2, extitem_len);
                    extitem_offset += 2;

                    tvbuff_t *extitem_tvb = tvb_new_subset_length(tvb, offset + extlist_offset + extitem_offset, extitem_len);
                    proto_item *item_extdata = proto_tree_add_item(tree_ext, hf_sessext_data, extitem_tvb, 0, tvb_captured_length(extitem_tvb), ENC_NA);
                    proto_tree *tree_extdata = proto_item_add_subtree(item_extdata, ett_sessext_data);

                    int sublen = dissector_try_uint(sess_ext_dissectors, extitem_type, extitem_tvb, pinfo, tree_extdata);
                    if (sublen == 0) {
                        expert_add_info(pinfo, item_type, &ei_invalid_sessext_type);
                    }
                    extitem_offset += extitem_len;

                    proto_item_set_len(item_ext, extitem_offset);
                    extlist_offset += extitem_offset;

                    const gchar *extitem_name = val_to_str(extitem_type, sessext_type_vals, "type 0x%" PRIx32);
                    proto_item_append_text(item_ext, ": %s", extitem_name);
                    if (is_critical) {
                        proto_item_append_text(item_ext, ", CRITICAL");
                    }
                }
                // advance regardless of any internal offset processing
                offset += extlist_len;

                if (frame_loc_valid(&(tx_peer->sess_init_seen))) {
                    if (tcpcl_analyze_sequence) {
                        if (!frame_loc_equal(&(tx_peer->sess_init_seen), cur_loc)) {
                            expert_add_info(pinfo, item_msg, &ei_sess_init_duplicate);
                        }
                    }
                }
                else {
                    tx_peer->sess_init_seen = *cur_loc;
                    tx_peer->keepalive = keepalive;
                    tx_peer->segment_mru = seg_mru;
                    tx_peer->transfer_mru = xfer_mru;
                }

                break;
            }
            case TCPCL_MSGTYPE_SESS_TERM: {
                guint8 flags = tvb_get_guint8(tvb, offset);
                proto_tree_add_bitmask(tree_msg, tvb, offset, hf_sess_term_flags, ett_sess_term_flags, sess_term_flags, ENC_BIG_ENDIAN);
                offset += 1;

                guint8 reason = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(tree_msg, hf_sess_term_reason, tvb, offset, 1, reason);
                offset += 1;

                if (frame_loc_valid(&(tx_peer->sess_term_seen))) {
                    if (tcpcl_analyze_sequence) {
                        if (!frame_loc_equal(&(tx_peer->sess_term_seen), cur_loc)) {
                            expert_add_info(pinfo, item_msg, &ei_sess_term_duplicate);
                        }
                    }
                }
                else {
                    tx_peer->sess_term_seen = *cur_loc;
                    tx_peer->sess_term_reason = reason;
                }

                if (tcpcl_analyze_sequence) {
                    if (frame_loc_valid(&(rx_peer->sess_term_seen))) {
                        proto_item *item_rel = proto_tree_add_uint(tree_msg, hf_sess_term_related, tvb, 0, 0, rx_peer->sess_term_seen.frame_num);
                        PROTO_ITEM_SET_GENERATED(item_rel);

                        // Is this message after the other SESS_TERM?
                        if (frame_loc_compare(&(tx_peer->sess_term_seen), &(rx_peer->sess_term_seen), NULL) > 0) {
                            if (!(flags & TCPCL_SESS_TERM_FLAG_REPLY)) {
                                expert_add_info(pinfo, item_msg, &ei_sess_term_reply_flag);
                            }
                        }
                    }
                }

                break;
            }
            case TCPCL_MSGTYPE_XFER_SEGMENT:{
                guint8 flags = tvb_get_guint8(tvb, offset);
                proto_item *item_flags = proto_tree_add_bitmask(tree_msg, tvb, offset, hf_xfer_flags, ett_xfer_flags, xfer_flags, ENC_BIG_ENDIAN);
                offset += 1;

                guint64 xfer_id = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_item *item_xfer_id = proto_tree_add_uint64(tree_msg, hf_xfer_id, tvb, offset, 8, xfer_id);
                offset += 8;

                if (flags & TCPCL_TRANSFER_FLAG_START) {
                    guint32 extlist_len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                    proto_tree_add_uint(tree_msg, hf_xfer_segment_extlist_len, tvb, offset, 4, extlist_len);
                    offset += 4;

                    gint extlist_offset = 0;
                    while (extlist_offset < (int)extlist_len) {
                        gint extitem_offset = 0;
                        proto_item *item_ext = proto_tree_add_item(tree_msg, hf_xferext_tree, tvb, offset + extlist_offset, 0, ENC_NA);
                        proto_tree *tree_ext = proto_item_add_subtree(item_ext, ett_xferext);

                        guint8 extitem_flags = tvb_get_guint8(tvb, offset + extlist_offset + extitem_offset);
                        proto_tree_add_bitmask(tree_ext, tvb, offset + extlist_offset + extitem_offset, hf_xferext_flags, ett_xferext_flags, xferext_flags, ENC_BIG_ENDIAN);
                        extitem_offset += 1;
                        const gboolean is_critical = (extitem_flags & TCPCL_EXTENSION_FLAG_CRITICAL);
                        if (is_critical) {
                            expert_add_info(pinfo, item_ext, &ei_extitem_critical);
                        }

                        guint32 extitem_type = tvb_get_guint16(tvb, offset + extlist_offset + extitem_offset, ENC_BIG_ENDIAN);
                        proto_item *item_type = proto_tree_add_uint(tree_ext, hf_xferext_type, tvb, offset + extlist_offset + extitem_offset, 2, extitem_type);
                        extitem_offset += 2;

                        guint32 extitem_len = tvb_get_guint16(tvb, offset + extlist_offset + extitem_offset, ENC_BIG_ENDIAN);
                        proto_tree_add_uint(tree_ext, hf_xferext_len, tvb, offset + extlist_offset + extitem_offset, 2, extitem_len);
                        extitem_offset += 2;

                        tvbuff_t *extitem_tvb = tvb_new_subset_length(tvb, offset + extlist_offset + extitem_offset, extitem_len);
                        proto_item *item_extdata = proto_tree_add_item(tree_ext, hf_xferext_data, extitem_tvb, 0, tvb_captured_length(extitem_tvb), ENC_NA);
                        proto_tree *tree_extdata = proto_item_add_subtree(item_extdata, ett_xferext_data);

                        frame_loc_t *extitem_loc = frame_loc_new(pinfo, extitem_tvb, 0);
                        tcpcl_peer_associate_transfer(tx_peer, extitem_loc, xfer_id);
                        int sublen = dissector_try_uint(xfer_ext_dissectors, extitem_type, extitem_tvb, pinfo, tree_extdata);
                        if (sublen == 0) {
                            expert_add_info(pinfo, item_type, &ei_invalid_xferext_type);
                        }
                        extitem_offset += extitem_len;

                        const gchar *extitem_name = val_to_str(extitem_type, xferext_type_vals, "type 0x%" PRIx32);
                        proto_item_append_text(item_ext, ": %s", extitem_name);
                        if (is_critical) {
                            proto_item_append_text(item_ext, ", CRITICAL");
                        }

                        proto_item_set_len(item_ext, extitem_offset);
                        extlist_offset += extitem_offset;

                        frame_loc_delete(extitem_loc);
                    }
                    // advance regardless of any internal offset processing
                    offset += extlist_len;
                }

                guint64 data_len = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_item *item_len = proto_tree_add_uint64(tree_msg, hf_xfer_segment_data_len, tvb, offset, 8, data_len);
                offset += 8;

                if (data_len > rx_peer->segment_mru) {
                    expert_add_info(pinfo, item_len, &ei_xfer_seg_over_seg_mru);
                }

                // Treat data as payload layer
                const gint data_offset = offset;
                offset += data_len;
                payload_len = data_len;

                wmem_strbuf_append_printf(suffix_text, ", Xfer ID: %" PRIu64, xfer_id);

                if (flags) {
                    wmem_strbuf_append(suffix_text, ", Flags: ");
                    gboolean sep = FALSE;
                    if (flags & TCPCL_TRANSFER_FLAG_START) {
                        wmem_strbuf_append(suffix_text, "START");
                        sep = TRUE;
                    }
                    if (flags & TCPCL_TRANSFER_FLAG_END) {
                        if (sep) {
                            wmem_strbuf_append(suffix_text, "|");
                        }
                        wmem_strbuf_append(suffix_text, "END");
                        sep = TRUE;
                    }
                }

                if (tcpcl_analyze_sequence) {
                    tcpcl_transfer_t *xfer = get_or_create_transfer_t(tx_peer->transfers, xfer_id);

                    // Add or get the segment metadata
                    seg_meta_t *seg_meta = seg_meta_new(pinfo, cur_loc);
                    GSequenceIter *iter = g_sequence_lookup(xfer->seg_list, seg_meta, segment_compare_loc, NULL);
                    if (iter) {
                        seg_meta_delete(seg_meta);
                        seg_meta = g_sequence_get(iter);
                    }
                    else {
                        iter = g_sequence_insert_sorted(xfer->seg_list, seg_meta, segment_compare_loc, NULL);
                        // Set for new item
                        seg_meta->flags = flags;
                    }

                    // mark start-of-transfer
                    if (!(seg_meta->related_start)) {
                        seg_meta_t *seg_front = g_sequence_get(g_sequence_get_begin_iter(xfer->seg_list));
                        if (seg_front && (seg_front->flags & TCPCL_TRANSFER_FLAG_START)) {
                            seg_meta->related_start = seg_front;
                        }
                    }

                    // accumulate segment sizes
                    guint64 prev_seen_len;
                    if (g_sequence_iter_is_begin(iter)) {
                        if (!(flags & TCPCL_TRANSFER_FLAG_START)) {
                            expert_add_info(pinfo, item_flags, &ei_xfer_seg_missing_start);
                        }
                        prev_seen_len = 0;
                    }
                    else {
                        const seg_meta_t *seg_prev = g_sequence_get(g_sequence_iter_prev(iter));
                        if (flags & TCPCL_TRANSFER_FLAG_START) {
                            expert_add_info(pinfo, item_flags, &ei_xfer_seg_duplicate_start);
                        }
                        prev_seen_len = seg_prev->seen_len;
                    }
                    if (g_sequence_iter_is_end(g_sequence_iter_next(iter))) {
                        if (!(flags & TCPCL_TRANSFER_FLAG_END)) {
                            expert_add_info(pinfo, item_flags, &ei_xfer_seg_missing_end);
                        }
                    }
                    else {
                        if (flags & TCPCL_TRANSFER_FLAG_END) {
                            expert_add_info(pinfo, item_flags, &ei_xfer_seg_duplicate_end);
                        }
                    }
                    seg_meta->seen_len = prev_seen_len + data_len;

                    proto_item *item_seen = proto_tree_add_uint64(tree_msg, hf_xfer_segment_seen_len, tvb, 0, 0, seg_meta->seen_len);
                    PROTO_ITEM_SET_GENERATED(item_seen);
                    if (seg_meta->seen_len > rx_peer->transfer_mru) {
                        expert_add_info(pinfo, item_seen, &ei_xferload_over_xfer_mru);
                    }
                    if (xfer->total_length) {
                        if (seg_meta->seen_len > *(xfer->total_length)) {
                            expert_add_info(pinfo, item_seen, &ei_xfer_seg_over_total_len);
                        }
                        else if ((flags & TCPCL_TRANSFER_FLAG_END)
                            && (seg_meta->seen_len != *(xfer->total_length))) {
                            expert_add_info(pinfo, item_seen, &ei_xfer_seg_mismatch_total_len);
                        }
                        proto_item *item_total = proto_tree_add_uint64(tree_msg, hf_xfer_total_len, tvb, 0, 0, *(xfer->total_length));
                        PROTO_ITEM_SET_GENERATED(item_total);
                    }

                    if (seg_meta->related_start) {
                        proto_item *item_rel = proto_tree_add_uint(tree_msg, hf_xfer_segment_related_start, tvb, 0, 0, seg_meta->related_start->frame_loc.frame_num);
                        PROTO_ITEM_SET_GENERATED(item_rel);

                        nstime_t td;
                        nstime_delta(&td, &(seg_meta->frame_time), &(seg_meta->related_start->frame_time));
                        proto_item *item_td = proto_tree_add_time(tree_msg, hf_xfer_segment_time_start, tvb, 0, 0, &td);
                        PROTO_ITEM_SET_GENERATED(item_td);
                    }
                    if (seg_meta->related_ack) {
                        proto_item *item_rel = proto_tree_add_uint(tree_msg, hf_xfer_segment_related_ack, tvb, 0, 0, seg_meta->related_ack->frame_loc.frame_num);
                        PROTO_ITEM_SET_GENERATED(item_rel);

                        nstime_t td;
                        nstime_delta(&td, &(seg_meta->related_ack->frame_time), &(seg_meta->frame_time));
                        proto_item *item_td = proto_tree_add_time(tree_msg, hf_xfer_segment_time_diff, tvb, 0, 0, &td);
                        PROTO_ITEM_SET_GENERATED(item_td);

                    }
                    else {
                        expert_add_info(pinfo, item_msg, &ei_xfer_seg_no_relation);
                    }
                }

                if (tcpcl_desegment_transfer) {
                    // wireshark fragment set IDs are 32-bits only
                    const guint32 corr_id = xfer_id & 0xFFFFFFFF;
                    if (corr_id != xfer_id) {
                        expert_add_info(pinfo, item_xfer_id, &ei_xfer_seg_large_xferid);
                    }
                    else {
                        // Reassemble the segments
                        const void *data_load = tvb_memdup(wmem_packet_scope(), tvb, data_offset, data_len);
                        fragment_head *xferload_frag_msg = fragment_add_seq_next(
                                &tcpcl_reassembly_table,
                                tvb, data_offset, pinfo,
                                corr_id,
                                data_load, data_len,
                                !(flags & TCPCL_TRANSFER_FLAG_END)
                        );

                        gboolean update_info = TRUE;
                        xferload_tvb = process_reassembled_data(
                                tvb, data_offset, pinfo,
                                "Reassembled Transfer",
                                xferload_frag_msg,
                                &xferload_frag_items,
                                &update_info,
                                proto_tree_get_parent_tree(tree)
                        );
                    }
                }
                else {
                    // show the segment data in isolation
                    tvbuff_t *xferdata_tvb = tvb_new_subset_length(tvb, data_offset, data_len);
                    call_data_dissector(
                        xferdata_tvb,
                        pinfo,
                        proto_tree_get_parent_tree(tree)
                    );
                }

                break;
            }
            case TCPCL_MSGTYPE_XFER_ACK:{
                guint8 flags = tvb_get_guint8(tvb, offset);
                proto_item *item_flags = proto_tree_add_bitmask(tree_msg, tvb, offset, hf_xfer_flags, ett_xfer_flags, xfer_flags, ENC_BIG_ENDIAN);
                offset += 1;

                guint64 xfer_id = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint64(tree_msg, hf_xfer_id, tvb, offset, 8, xfer_id);
                offset += 8;

                guint64 ack_len = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint64(tree_msg, hf_xfer_ack_ack_len, tvb, offset, 8, ack_len);
                offset += 8;

                wmem_strbuf_append_printf(suffix_text, ", Xfer ID: %" PRIu64, xfer_id);

                if (flags) {
                    wmem_strbuf_append(suffix_text, ", Flags: ");
                    gboolean sep = FALSE;
                    if (flags & TCPCL_TRANSFER_FLAG_START) {
                        wmem_strbuf_append(suffix_text, "START");
                        sep = TRUE;
                    }
                    if (flags & TCPCL_TRANSFER_FLAG_END) {
                        if (sep) {
                            wmem_strbuf_append(suffix_text, "|");
                        }
                        wmem_strbuf_append(suffix_text, "END");
                        sep = TRUE;
                    }
                }

                if (tcpcl_analyze_sequence) {
                    tcpcl_transfer_t *xfer = get_or_create_transfer_t(rx_peer->transfers, xfer_id);

                    // Add or get the ack metadata
                    ack_meta_t *ack_meta = ack_meta_new(pinfo, cur_loc);
                    GSequenceIter *iter = g_sequence_lookup(xfer->ack_list, ack_meta, ack_compare_loc, NULL);
                    if (iter) {
                        ack_meta_delete(ack_meta);
                        ack_meta = g_sequence_get(iter);
                    }
                    else {
                        iter = g_sequence_insert_sorted(xfer->ack_list, ack_meta, ack_compare_loc, NULL);
                        // Set for new item
                        ack_meta->flags = flags;
                        ack_meta->seen_len = ack_len;
                    }

                    // mark start-of-transfer
                    if (!(ack_meta->related_start)) {
                        seg_meta_t *seg_front = g_sequence_get(g_sequence_get_begin_iter(xfer->seg_list));
                        if (seg_front && (seg_front->flags & TCPCL_TRANSFER_FLAG_START)) {
                            ack_meta->related_start = seg_front;
                        }
                    }

                    // Assemble both of the links here, as ACK will always follow segment
                    if (!(ack_meta->related_seg)) {
                        GSequenceIter *seg_iter = g_sequence_get_begin_iter(xfer->seg_list);
                        for (; !g_sequence_iter_is_end(seg_iter); seg_iter = g_sequence_iter_next(seg_iter)) {
                            seg_meta_t *seg_meta = g_sequence_get(seg_iter);
                            if (seg_meta->seen_len == ack_meta->seen_len) {
                                seg_meta->related_ack = ack_meta;
                                ack_meta->related_seg = seg_meta;
                            }
                        }
                    }

                    if (xfer->total_length) {
                        proto_item *item_total = proto_tree_add_uint64(tree_msg, hf_xfer_total_len, tvb, 0, 0, *(xfer->total_length));
                        PROTO_ITEM_SET_GENERATED(item_total);
                    }
                    if (ack_meta->related_start) {
                        proto_item *item_rel = proto_tree_add_uint(tree_msg, hf_xfer_segment_related_start, tvb, 0, 0, ack_meta->related_start->frame_loc.frame_num);
                        PROTO_ITEM_SET_GENERATED(item_rel);

                        nstime_t td;
                        nstime_delta(&td, &(ack_meta->frame_time), &(ack_meta->related_start->frame_time));
                        proto_item *item_td = proto_tree_add_time(tree_msg, hf_xfer_segment_time_start, tvb, 0, 0, &td);
                        PROTO_ITEM_SET_GENERATED(item_td);
                    }
                    if (ack_meta->related_seg) {
                        proto_item *item_rel = proto_tree_add_uint(tree_msg, hf_xfer_ack_related_seg, tvb, 0, 0, ack_meta->related_seg->frame_loc.frame_num);
                        PROTO_ITEM_SET_GENERATED(item_rel);

                        nstime_t td;
                        nstime_delta(&td, &(ack_meta->frame_time), &(ack_meta->related_seg->frame_time));
                        proto_item *item_td = proto_tree_add_time(tree_msg, hf_xfer_ack_time_diff, tvb, 0, 0, &td);
                        PROTO_ITEM_SET_GENERATED(item_td);

                        if (ack_meta->flags != ack_meta->related_seg->flags) {
                            expert_add_info(pinfo, item_flags, &ei_xfer_ack_mismatch_flags);
                        }
                    }
                    else {
                        expert_add_info(pinfo, item_msg, &ei_xfer_ack_no_relation);
                    }
                }

                break;
            }
            case TCPCL_MSGTYPE_XFER_REFUSE: {
                guint8 reason = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(tree_msg, hf_xfer_refuse_reason, tvb, offset, 1, reason);
                offset += 1;

                guint64 xfer_id = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_item *item_xfer_id = proto_tree_add_uint64(tree_msg, hf_xfer_id, tvb, offset, 8, xfer_id);
                offset += 8;

                wmem_strbuf_append_printf(suffix_text, ", Xfer ID: %" PRIu64, xfer_id);

                if (tcpcl_analyze_sequence) {
                    const tcpcl_transfer_t *xfer = g_hash_table_lookup(rx_peer->transfers, &xfer_id);
                    const seg_meta_t *seg_last = NULL;
                    if (xfer) {
                        if (!g_sequence_is_empty(xfer->seg_list)) {
                            GSequenceIter *seg_iter = g_sequence_get_end_iter(xfer->seg_list);
                            seg_iter = g_sequence_iter_prev(seg_iter);
                            seg_last = g_sequence_get(seg_iter);
                        }
                    }

                    if (seg_last) {
                        proto_item *item_rel = proto_tree_add_uint(tree_msg, hf_xfer_refuse_related_seg, tvb, 0, 0, seg_last->frame_loc.frame_num);
                        PROTO_ITEM_SET_GENERATED(item_rel);
                    }
                    else {
                        expert_add_info(pinfo, item_xfer_id, &ei_xfer_refuse_no_transfer);
                    }
                }

                break;
            }
            case TCPCL_MSGTYPE_KEEPALIVE: {
                break;
            }
            case TCPCL_MSGTYPE_MSG_REJECT: {
                guint8 reason = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(tree_msg, hf_msg_reject_reason, tvb, offset, 1, reason);
                offset += 1;

                guint8 rej_head = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(tree_msg, hf_msg_reject_head, tvb, offset, 1, rej_head);
                offset += 1;

                break;
            }
            default:
                expert_add_info(pinfo, item_msg, &ei_invalid_msg_type);
                break;
        }

        proto_item_set_len(item_msg, offset - payload_len);
        proto_item_append_text(item_msg, ": %s%s", msgtype_name, wmem_strbuf_get_str(suffix_text));
        wmem_strbuf_finalize(suffix_text);

        if (tcpcl_analyze_sequence) {
            // This message is before SESS_INIT (but is not the SESS_INIT)
            const gint cmp_sess_init = frame_loc_compare(cur_loc, &(tx_peer->sess_init_seen), NULL);
            if (!frame_loc_valid(&(tx_peer->sess_init_seen))
                || ((msgtype == TCPCL_MSGTYPE_SESS_INIT) && (cmp_sess_init < 0))
                || ((msgtype != TCPCL_MSGTYPE_SESS_INIT) && (cmp_sess_init <= 0))) {
                expert_add_info(pinfo, item_msg, &ei_sess_init_missing);
            }
        }
    }

    if (msgtype_name) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msgtype_name);
    }

    try_negotiate(tcpcl_convo, pinfo, cur_loc);
    // Show negotiation results
    if (is_contact) {
        if (tcpcl_convo->contact_negotiated) {
            {
                proto_item *item_nego = proto_tree_add_uint(tree_msg, hf_chdr_related, tvb, 0, 0, rx_peer->chdr_seen.frame_num);
                PROTO_ITEM_SET_GENERATED(item_nego);
            }
            {
                proto_item *item_nego = proto_tree_add_boolean(tree_msg, hf_negotiate_use_tls, tvb, 0, 0, tcpcl_convo->session_use_tls);
                PROTO_ITEM_SET_GENERATED(item_nego);
            }
        }
    }
    else if (msgtype == TCPCL_MSGTYPE_SESS_INIT) {
        if (tcpcl_convo->sess_negotiated) {
            {
                proto_item *item_nego = proto_tree_add_uint(tree_msg, hf_sess_init_related, tvb, 0, 0, rx_peer->sess_init_seen.frame_num);
                PROTO_ITEM_SET_GENERATED(item_nego);
            }
            {
                proto_item *item_nego = proto_tree_add_uint(tree_msg, hf_negotiate_keepalive, tvb, 0, 0, tcpcl_convo->sess_keepalive);
                PROTO_ITEM_SET_GENERATED(item_nego);
            }
        }
    }

    if (xferload_tvb) {
        col_append_str(pinfo->cinfo, COL_INFO, " [Bundle]");
        gint sublen = 0;

        if (tcpcl_decode_bundle) {
            if (handle_bp) {
                sublen = call_dissector(
                    handle_bp,
                    xferload_tvb,
                    pinfo,
                    proto_tree_get_parent_tree(tree)
                );
            }
        }
        if (sublen == 0) {
            if (dissect_media) {
                sublen = dissector_try_string(
                    dissect_media,
                    "application/cbor",
                    xferload_tvb,
                    pinfo,
                    proto_tree_get_parent_tree(tree),
                    data
                );
            }
        }
        if (sublen == 0) {
            call_data_dissector(
                xferload_tvb,
                pinfo,
                proto_tree_get_parent_tree(tree)
            );
        }
    }

    frame_loc_delete(cur_loc);
    return offset;
}

/// Top-level protocol dissector
static int dissect_tcpcl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    /* Retrieve information from conversation, or add it if it isn't
     * there yet */
    conversation_t *convo = find_or_create_conversation(pinfo);
    tcpcl_conversation_t *tcpcl_convo = (tcpcl_conversation_t *)conversation_get_proto_data(convo, proto_tcpcl);
    g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "dissect_tcpcl() at %d ...\n", pinfo->num);
    if (!tcpcl_convo) {
        tcpcl_convo = tcpcl_conversation_new();
        conversation_add_proto_data(convo, proto_tcpcl, tcpcl_convo);
        // Assume the first source is the active node
        copy_address_wmem(wmem_file_scope(), &(tcpcl_convo->active->addr), &(pinfo->src));
        tcpcl_convo->active->port = pinfo->srcport;
        copy_address_wmem(wmem_file_scope(), &(tcpcl_convo->passive->addr), &(pinfo->dst));
        tcpcl_convo->passive->port = pinfo->destport;
    }

    {
        const gchar *proto_name = col_get_text(pinfo->cinfo, COL_PROTOCOL);
        if (proto_name && (strncmp(proto_name, "TCPCLv4", 8) != 0)) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCPCLv4");
            col_clear(pinfo->cinfo, COL_INFO);
        }
    }

    proto_item *item_tcpcl = proto_tree_add_item(tree, hf_tcpcl, tvb, 0, 0, ENC_NA);
    proto_tree *tree_tcpcl = proto_item_add_subtree(item_tcpcl, ett_tcpcl);

    tcp_dissect_pdus(tvb, pinfo, tree_tcpcl, TRUE, 1, get_message_len, dissect_message, data);

    const guint buflen = tvb_captured_length(tvb);
    proto_item_set_len(item_tcpcl, buflen);

    return buflen;
}

/// Re-initialize after a configuration change
static void reinit_tcpcl(void) {
}

static int dissect_xferext_transferlen(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    conversation_t *convo = find_or_create_conversation(pinfo);
    tcpcl_conversation_t *tcpcl_convo = (tcpcl_conversation_t *)conversation_get_proto_data(convo, proto_tcpcl);
    tcpcl_peer_t *tx_peer, *rx_peer;
    if (tcpcl_convo) {
        get_peers(&tx_peer, &rx_peer, tcpcl_convo, pinfo);
    }
    else {
        tx_peer = NULL;
        rx_peer = NULL;
    }
    int offset = 0;

    guint64 total_len = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
    proto_item *item_len = proto_tree_add_uint64(tree, hf_xferext_transferlen_total_len, tvb, offset, 8, total_len);
    offset += 8;
    if (total_len > rx_peer->transfer_mru) {
        expert_add_info(pinfo, item_len, &ei_xferload_over_xfer_mru);
    }

    if (tcpcl_analyze_sequence && tcpcl_convo) {
        frame_loc_t *key = frame_loc_new(pinfo, tvb, 0);
        guint64 *xfer_id = g_hash_table_lookup(tx_peer->frame_loc_to_transfer, key);
        if (xfer_id) {
            tcpcl_transfer_t *xfer = get_or_create_transfer_t(tx_peer->transfers, *xfer_id);
            xfer->total_length = guint64_new(total_len);
        }
        frame_loc_delete(key);
    }

    return tvb_captured_length(tvb);
}

/// Overall registration of the protocol
static void proto_register_tcpcl(void) {
    g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "proto_register_tcpcl()\n");
    proto_tcpcl = proto_register_protocol(
        "DTN TCP Convergence Layer Protocol Version 4", /* name */
        "TCPCLv4", /* short name */
        "tcpclv4" /* abbrev */
    );

    proto_register_field_array(proto_tcpcl, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_tcpcl);
    expert_register_field_array(expert, expertitems, array_length(expertitems));

    handle_tcpcl = register_dissector("tcpclv4", dissect_tcpcl, proto_tcpcl);
    sess_ext_dissectors = register_dissector_table("tcpclv4.sess_ext", "TCPCLv4 Session Extension", proto_tcpcl, FT_UINT16, BASE_HEX);
    xfer_ext_dissectors = register_dissector_table("tcpclv4.xfer_ext", "TCPCLv4 Transfer Extension", proto_tcpcl, FT_UINT16, BASE_HEX);

    module_t *module_tcpcl = prefs_register_protocol(proto_tcpcl, reinit_tcpcl);
    /*
    prefs_register_bool_preference(
        module_tcpcl,
        "resync_unkown_message",
        "Attempt resynchronization on unknown message",
        "If the capture starts mid-session, there will be no Contact Header"
        "and may not start on a message boundary. In this case, any ",
        &tcpcl_resync_unkown_message
    );
    */
    prefs_register_bool_preference(
        module_tcpcl,
        "analyze_sequence",
        "Analyze message sequences",
        "Whether the TCPCLv4 dissector should analyze the sequencing of "
        "the messages within each session.",
        &tcpcl_analyze_sequence
    );
    prefs_register_bool_preference(
        module_tcpcl,
        "desegment_transfer",
        "Reassemble the segments of each transfer",
        "Whether the TCPCLv4 dissector should combine the sequential segments "
        "of a transfer into the full bundle being transfered."
        "To use this option, you must also enable "
        "\"Allow subdissectors to reassemble TCP streams\" "
        "in the TCP protocol settings.",
        &tcpcl_desegment_transfer
    );
    prefs_register_bool_preference(
        module_tcpcl,
        "decode_bundle",
        "Decode bundle data",
        "If enabled, the bundle will be decoded as BPv7 content. "
        "Otherwise, it is assumed to be plain CBOR.",
        &tcpcl_decode_bundle
    );

    reassembly_table_register(
        &tcpcl_reassembly_table,
        &addresses_ports_reassembly_table_functions
    );

    /* Packaged extensions */
}

static void proto_reg_handoff_tcpcl(void) {
    g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "proto_reg_handoff_tcpcl()\n");
    dissector_add_uint_with_preference("tcp.port", TCPCL_PORT_NUM, handle_tcpcl);

    dissect_media = find_dissector_table("media_type");

    handle_ssl = find_dissector_add_dependency(TLS_DISSECTOR_NAME, proto_tcpcl);
    handle_bp = find_dissector_add_dependency("bpv7", proto_tcpcl);

    /* Packaged extensions */
    {
        dissector_handle_t dis_h = create_dissector_handle(dissect_xferext_transferlen, proto_tcpcl);
        dissector_add_uint("tcpclv4.xfer_ext", TCPCL_XFEREXT_TRANSFER_LEN, dis_h);
    }

    reinit_tcpcl();
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
    static proto_plugin plugin_tcpcl;
    plugin_tcpcl.register_protoinfo = proto_register_tcpcl;
    plugin_tcpcl.register_handoff = proto_reg_handoff_tcpcl;
    proto_register_plugin(&plugin_tcpcl);
}
