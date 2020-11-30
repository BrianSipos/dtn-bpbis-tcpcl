
#ifndef WIRESHARK_PLUGIN_SRC_PACKET_BPSEC_H_
#define WIRESHARK_PLUGIN_SRC_PACKET_BPSEC_H_

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <glib.h>

/** Abstract Security Block Security Context Flags.
 * Section 3.6.
 */
typedef enum {
    /// Security Parameters present
    ASB_HAS_PARAMS = 0x01,
    /// Security Source present
    ASB_HAS_SOURCE = 0x02,
} AsbFlag;

#endif /* WIRESHARK_PLUGIN_SRC_PACKET_BPSEC_H_ */
