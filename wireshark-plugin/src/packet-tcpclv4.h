
#ifndef WIRESHARK_PLUGIN_SRC_PACKET_TCPCLV4_H_
#define WIRESHARK_PLUGIN_SRC_PACKET_TCPCLV4_H_

#include <ws_symbol_export.h>

typedef enum {
    TCPCL_MSGTYPE_XFER_SEGMENT = 0x01,
    TCPCL_MSGTYPE_XFER_ACK = 0x02,
    TCPCL_MSGTYPE_XFER_REFUSE = 0x03,
    TCPCL_MSGTYPE_KEEPALIVE = 0x04,
    TCPCL_MSGTYPE_SESS_TERM = 0x05,
    TCPCL_MSGTYPE_MSG_REJECT = 0x06,
    TCPCL_MSGTYPE_SESS_INIT = 0x07,
} TcpclMessageType;

enum ContactFlag {
    TCPCL_CONTACT_FLAG_CANTLS = 0x01,
};

enum SessTermFlag {
    TCPCL_SESS_TERM_FLAG_REPLY = 0x01,
};

enum TransferFlag {
    TCPCL_TRANSFER_FLAG_START = 0x02,
    TCPCL_TRANSFER_FLAG_END = 0x01,
};

enum ExtensionFlag {
    TCPCL_EXTENSION_FLAG_CRITICAL = 0x01,
};

/// Interface for wireshark plugin
WS_DLL_PUBLIC const char plugin_version[];
/// Interface for wireshark plugin
WS_DLL_PUBLIC const char plugin_release[];
/// Interface for wireshark plugin
WS_DLL_PUBLIC void plugin_register(void);


#endif /* WIRESHARK_PLUGIN_SRC_PACKET_TCPCLV4_H_ */
