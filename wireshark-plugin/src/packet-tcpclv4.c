#include "packet-tcpclv4.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-ssl.h>
#include <epan/dissectors/packet-ssl-utils.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <stdio.h>

static const guint TCPCL_PORT_NUM = 4556;
/// Protocol handles
static int proto_tcpcl = -1;
static int proto_xferext_totallen = -1;

/// Dissector handles
static dissector_handle_t handle_tcpcl;
static dissector_handle_t handle_ssl;

/// Extension sub-dissectors
static dissector_table_t sess_ext_dissector;
static dissector_table_t xfer_ext_dissector;

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
    {0x01, "Extension Failure"},
    {0x02, "Completed"},
    {0x03, "No Resources"},
    {0x04, "Retransmit"},
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

static int hf_mhdr_tree = -1;
static int hf_mhdr_type = -1;
static int hf_sess_init_keepalive = -1;
static int hf_sess_init_seg_mru = -1;
static int hf_sess_init_xfer_mru = -1;
static int hf_sess_init_eid_len = -1;
static int hf_sess_init_eid_data = -1;
static int hf_sess_init_extlist_len = -1;

static int hf_sess_term_flags = -1;
static int hf_sess_term_flags_reply = -1;
static int hf_sess_term_reason = -1;

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
static int hf_xfer_segment_extlist_len = -1;
static int hf_xfer_segment_data_len = -1;
static int hf_xfer_segment_data_load = -1;
static int hf_xfer_ack_ack_len = -1;
static int hf_xfer_refuse_reason = -1;
static int hf_msg_reject_reason = -1;
static int hf_msg_reject_head = -1;

static int hf_xferext_totallen_total_len = -1;
/// Field definitions
static hf_register_info fields[] = {
    {&hf_tcpcl, {"TCP Convergence Layer Version 4", "tcpclv4", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_chdr_tree, {"TCPCLv4 Contact Header", "tcpclv4.chdr", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_chdr_magic, {"Protocol Magic", "tcpclv4.chdr.magic", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_chdr_version, {"Protocol Version", "tcpclv4.chdr.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_chdr_flags, {"Contact Flags", "tcpclv4.chdr.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_chdr_flags_cantls, {"CAN_TLS", "tcpclv4.chdr.can_tls", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL}},

    {&hf_mhdr_tree, {"TCPCLv4 Message", "tcpclv4.mhdr", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_mhdr_type, {"Message Type", "tcpclv4.mhdr.type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

    // Session extension fields
    {&hf_sessext_tree, {"Session Extension Item", "tcpclv4.sessext", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_sessext_flags, {"Item Flags", "tcpclv4.sessext.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_sessext_flags_crit, {"CRITICAL", "tcpclv4.sessext.flags.critical", FT_UINT8, BASE_DEC, NULL, TCPCL_EXTENSION_FLAG_CRITICAL, NULL, HFILL}},
    {&hf_sessext_type, {"Item Type", "tcpclv4.sessext.type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_sessext_len, {"Item Length", "tcpclv4.sessext.len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_sessext_data, {"Item Data", "tcpclv4.sessext.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    // Transfer extension fields
    {&hf_xferext_tree, {"Transfer Extension Item", "tcpclv4.xferext", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_xferext_flags, {"Item Flags", "tcpclv4.xferext.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_xferext_flags_crit, {"CRITICAL", "tcpclv4.xferext.flags.critical", FT_UINT8, BASE_DEC, NULL, TCPCL_EXTENSION_FLAG_CRITICAL, NULL, HFILL}},
    {&hf_xferext_type, {"Item Type", "tcpclv4.xferext.type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_xferext_len, {"Item Length", "tcpclv4.xferext.len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_xferext_data, {"Item Data", "tcpclv4.xferext.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    // Specific extensions
    {&hf_xferext_totallen_total_len, {"Total Length (octets)", "tcpclv4.xferext.totallen.total_len", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},

    // SESS_INIT fields
    {&hf_sess_init_keepalive, {"Keepalive Interval (s)", "tcpclv4.sess_init.keepalive", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_sess_init_seg_mru, {"Segment MRU (octets)", "tcpclv4.sess_init.seg_mru", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_sess_init_xfer_mru, {"Transfer MRU (octets)", "tcpclv4.sess_init.xfer_mru", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_sess_init_eid_len, {"EID Length (octets)", "tcpclv4.sess_init.eid_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_sess_init_eid_data, {"EID Data (UTF8)", "tcpclv4.sess_init.eid_data", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL}},
    {&hf_sess_init_extlist_len, {"Extension Items Length (octets)", "tcpclv4.sess_init.extlist_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    // SESS_TERM fields
    {&hf_sess_term_flags, {"Flags", "tcpclv4.sess_term.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_sess_term_flags_reply, {"REPLY", "tcpclv4.sess_term.flags.reply", FT_UINT8, BASE_DEC, NULL, TCPCL_SESS_TERM_FLAG_REPLY, NULL, HFILL}},
    {&hf_sess_term_reason, {"Reason", "tcpclv4.ses_term.reason", FT_UINT8, BASE_DEC, VALS(sess_term_reason_vals), 0x0, NULL, HFILL}},

    // Common transfer fields
    {&hf_xfer_flags, {"Transfer Flags", "tcpclv4.xfer_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_flags_start, {"START", "tcpclv4.xfer_flags.start", FT_UINT8, BASE_DEC, NULL, TCPCL_TRANSFER_FLAG_START, NULL, HFILL}},
    {&hf_xfer_flags_end, {"END", "tcpclv4.xfer_flags.end", FT_UINT8, BASE_DEC, NULL, TCPCL_TRANSFER_FLAG_END, NULL, HFILL}},
    {&hf_xfer_id, {"Transfer ID", "tcpclv4.xfer_id", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    // XFER_SEGMENT fields
    {&hf_xfer_segment_extlist_len, {"Extension Items Length (octets)", "tcpclv4.xfer_segment.extlist_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_segment_data_len, {"Data Length (octets)", "tcpclv4.xfer_segment.data_len", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_segment_data_load, {"Data", "tcpclv4.xfer_segment.data_load", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    // XFER_ACK fields
    {&hf_xfer_ack_ack_len, {"Acknowledged Length (octets)", "tcpclv4.xfer_ack.ack_len", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    // XFER_REFUSE fields
    {&hf_xfer_refuse_reason, {"Reason", "tcpclv4.xfer_refuse.reason", FT_UINT8, BASE_DEC, VALS(xfer_refuse_reason_vals), 0x0, NULL, HFILL}},
    // MSG_REJECT fields
    {&hf_msg_reject_reason, {"Reason", "tcpclv4.msg_reject.reason", FT_UINT8, BASE_DEC, VALS(msg_reject_reason_vals), 0x0, NULL, HFILL}},
    {&hf_msg_reject_head, {"Rejected Type", "tcpclv4.msg_reject.head", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
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
static int ett_tcpcl = -1;
static int ett_chdr = -1;
static int ett_chdr_flags = -1;
static int ett_chdr_badmagic = -1;
static int ett_mhdr = -1;
static int ett_sess_term_flags = -1;
static int ett_xfer_flags = -1;
static int ett_sessext = -1;
static int ett_sessext_flags = -1;
static int ett_xferext = -1;
static int ett_xferext_flags = -1;

static expert_field ei_invalid_magic = EI_INIT;
static expert_field ei_invalid_version = EI_INIT;
static expert_field ei_invalid_msg_type = EI_INIT;
static expert_field ei_invalid_sessext_type = EI_INIT;
static expert_field ei_invalid_xferext_type = EI_INIT;
static expert_field ei_extitem_critical = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_invalid_magic, { "tcpclv4.invalid_contact_magic", PI_PROTOCOL, PI_ERROR, "Magic string is invalid", EXPFILL}},
    {&ei_invalid_version, { "tcpclv4.invalid_contact_version", PI_PROTOCOL, PI_ERROR, "Protocol version mismatch", EXPFILL}},
    {&ei_invalid_msg_type, { "tcpclv4.unknown_message_type", PI_UNDECODED, PI_ERROR, "Message type is unknown", EXPFILL}},
    {&ei_invalid_sessext_type, { "tcpclv4.unknown_sessext_type", PI_UNDECODED, PI_WARN, "Session Extension type is unknown", EXPFILL}},
    {&ei_invalid_xferext_type, { "tcpclv4.unknown_xferext_type", PI_UNDECODED, PI_WARN, "Transfer Extension type is unknown", EXPFILL}},
    {&ei_extitem_critical, { "tcpclv4.extitem_critical", PI_REQUEST_CODE, PI_CHAT, "Extension Item is critical", EXPFILL}},
};

typedef struct {
    guint32 frame_num;
    gint raw_offset;
} frame_loc_t;

typedef struct {
    /// Address for this peer
    address addr;
    /// Port for the this peer
    guint32 port;

    /// Frame number in which the contact header starts
    frame_loc_t chdr_seen;
    /// Frame number in which the SESS_INIT message starts
    guint32 sess_init_seen;

    /// CAN_TLS flag from the contact header
    gboolean can_tls;

} tcpcl_peer_t;
#define TCPCL_PEER_INIT {ADDRESS_INIT_NONE, 0, {0, -1}, 0, FALSE}

typedef struct {
    /// Information for the active side of the session
    tcpcl_peer_t active;
    /// Information for the passive side of the session
    tcpcl_peer_t passive;

    /// True when contact negotiation is finished
    gboolean contact_negotiated;
    /// Derived use of TLS from @c can_tls of the peers
    gboolean session_use_tls;
    guint32 session_tls_start;

    /// True when session negotiation is finished
    gboolean sess_negotiated;
} tcpcl_conversation_t;
#define TCPCL_CONVERSATION_INIT {TCPCL_PEER_INIT, TCPCL_PEER_INIT, FALSE, FALSE, 0, FALSE}

static tcpcl_peer_t * get_peer(tcpcl_conversation_t *tcpcl_convo, const packet_info *pinfo) {
    const gboolean is_active = (
        addresses_equal(&(tcpcl_convo->active.addr), &(pinfo->src))
        && (tcpcl_convo->active.port == pinfo->srcport)
    );
    if (is_active) {
        return &(tcpcl_convo->active);
    }
    else {
        return &(tcpcl_convo->passive);
    }
}

static gboolean has_init_packet(const tcpcl_peer_t *peer) {
    return (peer->chdr_seen.raw_offset >= 0);
}

static gboolean is_init_packet(const tcpcl_peer_t *peer, const packet_info *pinfo, gint raw_off) {
    fprintf(stdout, "is_init_packet on %d+%d seen contact header on %d+%d\n",
        pinfo->num, raw_off,
        peer->chdr_seen.frame_num, peer->chdr_seen.raw_offset
    );
    return (
        (peer->chdr_seen.raw_offset < 0)
        || (
            (peer->chdr_seen.frame_num == pinfo->num)
            && (peer->chdr_seen.raw_offset == raw_off)
        )
    );
}

static void try_negotiate(tcpcl_conversation_t *tcpcl_convo, packet_info *pinfo _U_) {
    if (!(tcpcl_convo->contact_negotiated)
        && has_init_packet(&(tcpcl_convo->active))
        && has_init_packet(&(tcpcl_convo->passive))) {
        tcpcl_convo->session_use_tls = (
            tcpcl_convo->active.can_tls & tcpcl_convo->passive.can_tls
        );
        tcpcl_convo->contact_negotiated = TRUE;
        fprintf(stdout, "TCPCLv4 negotiated contact parameters: USE_TLS=%d\n", tcpcl_convo->session_use_tls);

        if (tcpcl_convo->session_use_tls && (tcpcl_convo->session_tls_start == 0)) {
            col_append_str(pinfo->cinfo, COL_INFO, ", STARTTLS");
            tcpcl_convo->session_tls_start = pinfo->num;
            ssl_starttls_ack(handle_ssl, pinfo, handle_tcpcl);
        }
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

    const tcpcl_peer_t *tcpcl_peer = get_peer(tcpcl_convo, pinfo);
    guint8 msgtype = 0;
    fprintf(stdout, "LEN scanning...\n");
    if (is_init_packet(tcpcl_peer, pinfo, tvb_raw_offset(tvb) + ext_offset)) {
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
                guint16 eid_len = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
                offset += 2;
                offset += eid_len;
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
    fprintf(stdout, "LEN decoded msg type %x, remain length %d, need length %d\n", msgtype, buflen - init_offset, needlen);
    return needlen;
}

static gint dissect_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    conversation_t *convo = find_or_create_conversation(pinfo);
    tcpcl_conversation_t *tcpcl_convo = (tcpcl_conversation_t *)conversation_get_proto_data(convo, proto_tcpcl);
    if (!tcpcl_convo) {
        return 0;
    }
    gint offset = 0;

    tcpcl_peer_t *tcpcl_peer = get_peer(tcpcl_convo, pinfo);
    const char *msgtype_name = NULL;
    fprintf(stdout, "DISSECT scanning...\n");
    if (is_init_packet(tcpcl_peer, pinfo, tvb_raw_offset(tvb))) {
        msgtype_name = "Contact Header";

        proto_item *item_chdr = proto_tree_add_item(tree, hf_chdr_tree, tvb, offset, 0, ENC_BIG_ENDIAN);
        proto_tree *tree_chdr = proto_item_add_subtree(item_chdr, ett_chdr);

        const void *magic_data = tvb_memdup(wmem_packet_scope(), tvb, offset, 4);
        proto_item *item_magic = proto_tree_add_bytes(tree_chdr, hf_chdr_magic, tvb, offset, 4, magic_data);
        offset += 4;
        if (strncmp((const char *)magic_data, "dtn!", 4) != 0) {
            expert_add_info(pinfo, item_magic, &ei_invalid_magic);
        }

        guint8 version = tvb_get_guint8(tvb, offset);
        proto_item *item_version = proto_tree_add_uint(tree_chdr, hf_chdr_version, tvb, offset, 1, version);
        offset += 1;
        if (version != 4) {
            expert_add_info(pinfo, item_version, &ei_invalid_version);
        }

        guint8 flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_bitmask(tree_chdr, tvb, offset, hf_chdr_flags, ett_chdr_flags, chdr_flags, ENC_BIG_ENDIAN);
        offset += 1;
        tcpcl_peer->can_tls = (flags & TCPCL_CONTACT_FLAG_CANTLS);

        proto_item_set_len(item_chdr, offset);

        tcpcl_peer->chdr_seen.frame_num = pinfo->num;
        tcpcl_peer->chdr_seen.raw_offset = tvb_raw_offset(tvb);
    }
    else {
        proto_item *item_msg = proto_tree_add_item(tree, hf_mhdr_tree, tvb, offset, 0, ENC_BIG_ENDIAN);
        proto_tree *tree_msg = proto_item_add_subtree(item_msg, ett_mhdr);

        guint8 msgtype = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree_msg, hf_mhdr_type, tvb, offset, 1, msgtype);
        offset += 1;
        fprintf(stdout, "DISSECT decoding msg type %x, buf length %d\n", msgtype, tvb_captured_length(tvb));

        wmem_strbuf_t *suffix_text = wmem_strbuf_new(wmem_packet_scope(), NULL);
        switch(msgtype) {
            case TCPCL_MSGTYPE_SESS_INIT: {
                msgtype_name = "SESS_INIT";

                guint16 keepalive = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint(tree_msg, hf_sess_init_keepalive, tvb, offset, 2, keepalive);
                offset += 2;

                guint64 seg_mru = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint64(tree_msg, hf_sess_init_seg_mru, tvb, offset, 8, seg_mru);
                offset += 8;

                guint64 xfer_mru = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint64(tree_msg, hf_sess_init_xfer_mru, tvb, offset, 8, xfer_mru);
                offset += 8;

                guint16 eid_len = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint(tree_msg, hf_sess_init_eid_len, tvb, offset, 2, eid_len);
                offset += 2;

                guint8 *eid_data = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, eid_len, ENC_UTF_8);
                proto_tree_add_string(tree_msg, hf_sess_init_eid_data, tvb, offset, eid_len, (const char *)eid_data);
                offset += eid_len;

                guint32 extlist_len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint(tree_msg, hf_sess_init_extlist_len, tvb, offset, 4, extlist_len);
                offset += 4;

                gint extlist_offset = 0;
                fprintf(stdout, "sessext length %d\n", extlist_len);
                while (extlist_offset < (int)extlist_len) {
                    gint extitem_offset = 0;
                    proto_item *item_ext = proto_tree_add_item(tree_msg, hf_sessext_tree, tvb, offset + extlist_offset, 0, ENC_BIG_ENDIAN);
                    proto_tree *tree_ext = proto_item_add_subtree(item_ext, ett_sessext);
                    fprintf(stdout, "sessext item at %d\n", extlist_offset);

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

                    guint32 extitem_len = tvb_get_guint32(tvb, offset + extlist_offset + extitem_offset, ENC_BIG_ENDIAN);
                    proto_tree_add_uint(tree_ext, hf_sessext_len, tvb, offset + extlist_offset + extitem_offset, 4, extitem_len);
                    extitem_offset += 4;

                    tvbuff_t *extitem_tvb = tvb_clone_offset_len(tvb, offset + extlist_offset + extitem_offset, extitem_len);
                    int sublen = dissector_try_uint(sess_ext_dissector, extitem_type, extitem_tvb, pinfo, tree_ext);
                    if (sublen == 0) {
                        expert_add_info(pinfo, item_type, &ei_invalid_sessext_type);

                        // Still add the raw data
                        const void *extitem_data = tvb_memdup(wmem_packet_scope(), tvb, offset + extlist_offset + extitem_offset, extitem_len);
                        proto_tree_add_bytes(tree_ext, hf_sessext_data, tvb, offset + extlist_offset + extitem_offset, extitem_len, extitem_data);
                    }
                    proto_item_append_text(item_ext, " (0x%x)", extitem_type);
                    extitem_offset += extitem_len;

                    proto_item_set_len(item_ext, extitem_offset);
                    extlist_offset += extitem_offset;
                }
                // advance regardless of any internal offset processing
                offset += extlist_len;

                break;
            }
            case TCPCL_MSGTYPE_SESS_TERM: {
                msgtype_name = "SESS_TERM";

                tvb_get_guint8(tvb, offset);
                proto_tree_add_bitmask(tree_msg, tvb, offset, hf_sess_term_flags, ett_sess_term_flags, sess_term_flags, ENC_BIG_ENDIAN);
                offset += 1;

                guint8 reason = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(tree_msg, hf_sess_term_reason, tvb, offset, 1, reason);
                offset += 1;

                break;
            }
            case TCPCL_MSGTYPE_XFER_SEGMENT:{
                msgtype_name = "XFER_SEGMENT";

                guint8 flags = tvb_get_guint8(tvb, offset);
                proto_tree_add_bitmask(tree_msg, tvb, offset, hf_xfer_flags, ett_xfer_flags, xfer_flags, ENC_BIG_ENDIAN);
                offset += 1;

                guint64 xfer_id = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint64(tree_msg, hf_xfer_id, tvb, offset, 8, xfer_id);
                offset += 8;

                if (flags & TCPCL_TRANSFER_FLAG_START) {
                    guint32 extlist_len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                    proto_tree_add_uint(tree_msg, hf_xfer_segment_extlist_len, tvb, offset, 4, extlist_len);
                    offset += 4;

                    gint extlist_offset = 0;
                    fprintf(stdout, "xferext length %d\n", extlist_len);
                    while (extlist_offset < (int)extlist_len) {
                        gint extitem_offset = 0;
                        proto_item *item_ext = proto_tree_add_item(tree_msg, hf_xferext_tree, tvb, offset + extlist_offset, 0, ENC_BIG_ENDIAN);
                        proto_tree *tree_ext = proto_item_add_subtree(item_ext, ett_xferext);
                        fprintf(stdout, "xferext item at %d\n", extlist_offset);

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

                        guint32 extitem_len = tvb_get_guint32(tvb, offset + extlist_offset + extitem_offset, ENC_BIG_ENDIAN);
                        proto_tree_add_uint(tree_ext, hf_xferext_len, tvb, offset + extlist_offset + extitem_offset, 4, extitem_len);
                        extitem_offset += 4;

                        tvbuff_t *extitem_tvb = tvb_clone_offset_len(tvb, offset + extlist_offset + extitem_offset, extitem_len);
                        int sublen = dissector_try_uint(xfer_ext_dissector, extitem_type, extitem_tvb, pinfo, tree_ext);
                        if (sublen == 0) {
                            expert_add_info(pinfo, item_type, &ei_invalid_xferext_type);

                            // Still add the raw data
                            const void *extitem_data = tvb_memdup(wmem_packet_scope(), tvb, offset + extlist_offset + extitem_offset, extitem_len);
                            proto_tree_add_bytes(tree_ext, hf_xferext_data, tvb, offset + extlist_offset + extitem_offset, extitem_len, extitem_data);
                        }
                        proto_item_append_text(item_ext, " (0x%x)", extitem_type);
                        extitem_offset += extitem_len;

                        proto_item_set_len(item_ext, extitem_offset);
                        extlist_offset += extitem_offset;
                    }
                    // advance regardless of any internal offset processing
                    offset += extlist_len;
                }

                guint64 data_len = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint64(tree_msg, hf_xfer_segment_data_len, tvb, offset, 8, data_len);
                offset += 8;

                const void *data_load = tvb_memdup(wmem_packet_scope(), tvb, offset, data_len);
                proto_tree_add_bytes(tree_msg, hf_xfer_segment_data_load, tvb, offset, data_len, data_load);
                offset += data_len;

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

                break;
            }
            case TCPCL_MSGTYPE_XFER_ACK:{
                msgtype_name = "XFER_ACK";

                guint8 flags = tvb_get_guint8(tvb, offset);
                proto_tree_add_bitmask(tree_msg, tvb, offset, hf_xfer_flags, ett_xfer_flags, xfer_flags, ENC_BIG_ENDIAN);
                offset += 1;

                guint64 xfer_id = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint64(tree_msg, hf_xfer_id, tvb, offset, 8, xfer_id);
                offset += 8;

                guint64 ack_len = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint64(tree_msg, hf_xfer_ack_ack_len, tvb, offset, 8, ack_len);
                offset += 8;

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

                break;
            }
            case TCPCL_MSGTYPE_XFER_REFUSE: {
                msgtype_name = "XFER_REFUSE";

                guint8 reason = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(tree_msg, hf_xfer_refuse_reason, tvb, offset, 1, reason);
                offset += 1;

                guint64 xfer_id = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint64(tree_msg, hf_xfer_id, tvb, offset, 8, xfer_id);
                offset += 8;

                break;
            }
            case TCPCL_MSGTYPE_KEEPALIVE: {
                msgtype_name = "KEEPALIVE";
                break;
            }
            case TCPCL_MSGTYPE_MSG_REJECT: {
                msgtype_name = "MSG_REJECT";

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

        proto_item_set_len(item_msg, offset);
        proto_item_append_text(item_msg, ", Type: %s (0x%x)%s", msgtype_name, msgtype, wmem_strbuf_get_str(suffix_text));
        wmem_strbuf_finalize(suffix_text);
    }

    const gchar *coltext = col_get_text(pinfo->cinfo, COL_INFO);
    if (coltext && strnlen(coltext, 1) > 0) {
        col_append_str(pinfo->cinfo, COL_INFO, ", ");
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", msgtype_name);

    try_negotiate(tcpcl_convo, pinfo);

    return offset;
}

static int dissect_tcpcl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    /* Retrieve information from conversation, or add it if it isn't
     * there yet */
    conversation_t *convo = find_or_create_conversation(pinfo);
    tcpcl_conversation_t *tcpcl_convo = (tcpcl_conversation_t *)conversation_get_proto_data(convo, proto_tcpcl);
    if (!tcpcl_convo) {
        tcpcl_convo = wmem_new(wmem_file_scope(), tcpcl_conversation_t);
        conversation_add_proto_data(convo, proto_tcpcl, tcpcl_convo);
        *tcpcl_convo = (tcpcl_conversation_t)TCPCL_CONVERSATION_INIT;

        // Assume the first source is the active node
        copy_address_wmem(wmem_file_scope(), &(tcpcl_convo->active.addr), &(pinfo->src));
        tcpcl_convo->active.port = pinfo->srcport;
        copy_address_wmem(wmem_file_scope(), &(tcpcl_convo->passive.addr), &(pinfo->dst));
        tcpcl_convo->passive.port = pinfo->destport;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCPCLv4");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);
    fprintf(stdout, "\n");

    proto_item *item_tcpcl = proto_tree_add_item(tree, hf_tcpcl, tvb, 0, 0, ENC_BIG_ENDIAN);
    proto_tree *tree_tcpcl = proto_item_add_subtree(item_tcpcl, ett_tcpcl);

    tcp_dissect_pdus(tvb, pinfo, tree_tcpcl, TRUE, 1, get_message_len, dissect_message, data);

    const guint buflen = tvb_captured_length(tvb);
    proto_item_set_len(item_tcpcl, buflen);

    return buflen;
}

static int dissect_xferext_totallen(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    int offset = 0;

    guint64 total_len = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_uint64(tree, hf_xferext_totallen_total_len, tvb, offset, 8, total_len);
    offset += 8;

    return tvb_captured_length(tvb);
}

static void reinit_tcpcl(void) {
    //pref_tcp_range = prefs_get_range_value("tcpclv4", "tcp.port");
}

static void proto_register_tcpcl(void) {
    proto_tcpcl = proto_register_protocol(
        "DTN TCP Convergence Layer Protocol Version 4", /* name */
        "TCPCLv4", /* short name */
        "tcpclv4" /* abbrev */
    );

    proto_register_field_array(proto_tcpcl, fields, array_length(fields));
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
        &ett_xferext,
        &ett_xferext_flags,
    };
    proto_register_subtree_array(ett, array_length(ett));
    sess_ext_dissector = register_dissector_table("tcpclv4.sess_ext", "TCPCLv4 Session Extension", proto_tcpcl, FT_UINT16, BASE_HEX);
    xfer_ext_dissector = register_dissector_table("tcpclv4.xfer_ext", "TCPCLv4 Transfer Extension", proto_tcpcl, FT_UINT16, BASE_HEX);

    expert_module_t *expert = expert_register_protocol(proto_tcpcl);
    expert_register_field_array(expert, expertitems, array_length(expertitems));

    handle_tcpcl = register_dissector("tcpclv4", dissect_tcpcl, proto_tcpcl);

    module_t *module_tcpcl = prefs_register_protocol(proto_tcpcl, reinit_tcpcl);
    (void)module_tcpcl;

    /* Packaged extensions */
    proto_xferext_totallen = proto_register_protocol(
        "DTN TCPCLv4 Transfer Total Length", /* name */
        "TCPCLv4-xferext-totallen", /* short name */
        "tcpclv4-xferext-totallen" /* abbrev */
    );
}

static void proto_reg_handoff_tcpcl(void) {
    dissector_add_uint_with_preference("tcp.port", TCPCL_PORT_NUM, handle_tcpcl);

    handle_ssl = find_dissector("ssl");

    /* Packaged extensions */
    {
        dissector_handle_t dis_h = create_dissector_handle(dissect_xferext_totallen, proto_xferext_totallen);
        dissector_add_uint("tcpclv4.xfer_ext", 1, dis_h);
    }
}

const char plugin_version[] = "0.0";

const char plugin_release[] = "2.6";

void plugin_register(void) {
    static proto_plugin plugin_tcpcl;
    plugin_tcpcl.register_protoinfo = proto_register_tcpcl;
    plugin_tcpcl.register_handoff = proto_reg_handoff_tcpcl;
    proto_register_plugin(&plugin_tcpcl);
}
