
#ifndef WIRESHARK_PLUGIN_SRC_PACKET_TCPCLV4_H_
#define WIRESHARK_PLUGIN_SRC_PACKET_TCPCLV4_H_

#include <ws_symbol_export.h>
#include <glib.h>
#include <epan/tvbuff.h>
#include <epan/packet_info.h>

typedef enum {
    TCPCL_MSGTYPE_INVALID = 0x00,
    TCPCL_MSGTYPE_XFER_SEGMENT = 0x01,
    TCPCL_MSGTYPE_XFER_ACK = 0x02,
    TCPCL_MSGTYPE_XFER_REFUSE = 0x03,
    TCPCL_MSGTYPE_KEEPALIVE = 0x04,
    TCPCL_MSGTYPE_SESS_TERM = 0x05,
    TCPCL_MSGTYPE_MSG_REJECT = 0x06,
    TCPCL_MSGTYPE_SESS_INIT = 0x07,
} TcpclMessageType;

typedef enum {
    TCPCL_SESSEXT_INVALID = 0x00,
} TcpclSessExtenionType;

typedef enum {
    TCPCL_XFEREXT_INVALID = 0x00,
    TCPCL_XFEREXT_TRANSFER_LEN = 0x01,
} TcpclXferExtenionType;

typedef enum {
    TCPCL_CONTACT_FLAG_CANTLS = 0x01,
} ContactFlag;

typedef enum {
    TCPCL_SESS_TERM_FLAG_REPLY = 0x01,
} SessTermFlag;

typedef enum {
    TCPCL_TRANSFER_FLAG_START = 0x02,
    TCPCL_TRANSFER_FLAG_END = 0x01,
} TransferFlag;

typedef enum {
    TCPCL_EXTENSION_FLAG_CRITICAL = 0x01,
} ExtensionFlag;

/// Finer grained locating than just the frame number
typedef struct {
    /// Index of the frame
    guint32 frame_num;
    /// Source index within the frame
    gint src_ix;
    /// Offset within the source TVB
    gint raw_offset;
} frame_loc_t;

#define FRAME_LOC_INIT {0, -1, -1}

void frame_loc_init(frame_loc_t *loc, const packet_info *pinfo, tvbuff_t *tvb, const gint offset);

/** Construct a new object on the file allocator.
 */
frame_loc_t * frame_loc_new(const packet_info *pinfo, tvbuff_t *tvb, const gint offset);

/** Function to match the GDestroyNotify signature.
 */
void frame_loc_delete(gpointer ptr);

/** Construct a new object on the file allocator.
 */
frame_loc_t * frame_loc_clone(const frame_loc_t *loc);

/** Determine if the frame location has been set.
 *
 * @param loc The location to check.
 * @return TRUE if the value is set.
 */
gboolean frame_loc_valid(const frame_loc_t *loc);

/** Function to match the GCompareDataFunc signature.
 */
gint frame_loc_compare(gconstpointer a, gconstpointer b, gpointer user_data);

/** Function to match the GCompareFunc signature.
 */
gboolean frame_loc_equal(gconstpointer a, gconstpointer b);

/** Function to match the GHashFunc signature.
 */
guint frame_loc_hash(gconstpointer key);

#endif /* WIRESHARK_PLUGIN_SRC_PACKET_TCPCLV4_H_ */
