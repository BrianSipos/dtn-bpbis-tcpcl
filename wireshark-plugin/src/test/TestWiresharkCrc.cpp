
#include <glib.h>
#include <wsutil/crc16.h>
#include <wsutil/crc32.h>
#include <gtest/gtest.h>

// Test from <http://reveng.sourceforge.net/crc-catalogue/16.htm#crc.cat.crc-16-ibm-sdlc>
TEST(TestWiresharkCrc, testCrc16Itu) {
    const char *buf = "123456789";
    const guint16 got = crc16_ccitt((const guint8 *)buf, strnlen(buf, 1024));
    EXPECT_EQ(0x906e, got);
}

// Test from <http://reveng.sourceforge.net/crc-catalogue/17plus.htm#crc.cat.crc-32>
TEST(TestWiresharkCrc, testCrc32Itu) {
    const char *buf = "123456789";
    const guint32 got = crc32_ccitt((const guint8 *)buf, strnlen(buf, 1024));
    EXPECT_EQ(0xcbf43926, got);
}

// Test from <http://reveng.sourceforge.net/crc-catalogue/17plus.htm#crc.cat.crc-32c>
TEST(TestWiresharkCrc, testCrc32C) {
    const char *buf = "123456789";
    const guint32 got = ~crc32c_calculate_no_swap((const guint8 *)buf, strnlen(buf, 1024), CRC32C_PRELOAD);
    EXPECT_EQ(0xe3069283, got);
}
