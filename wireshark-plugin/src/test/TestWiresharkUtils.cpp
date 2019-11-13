
#include <inttypes.h>
#include <glib.h>
#include <epan/value_string.h>
#include <epan/wmem/wmem_allocator.h>
#include <gtest/gtest.h>


static const value_string test_vals[]={
    {2, "Two"},
    {8, "Eight"},
    {0, NULL},
};

class TestWiresharkUtils : public testing::Test {
 protected:
    void SetUp() override {
        _alloc = wmem_allocator_new(WMEM_ALLOCATOR_STRICT);
    }
    void TearDown() override {
        wmem_destroy_allocator(_alloc);
        _alloc = nullptr;
    }

    wmem_allocator_t *_alloc = nullptr;
};

TEST_F(TestWiresharkUtils, testValueStringValToStrFound) {
    EXPECT_STREQ("Two", val_to_str_wmem(_alloc, 2, test_vals, "type %" PRIx32));
    EXPECT_STREQ("Eight", val_to_str_wmem(_alloc, 8, test_vals, "type %" PRIx32));
}

TEST_F(TestWiresharkUtils, testValueStringValToStrNotfound) {
    EXPECT_STREQ("type 0", val_to_str_wmem(_alloc, 0, test_vals, "type %" PRIx32));
    EXPECT_STREQ("type 3", val_to_str_wmem(_alloc, 3, test_vals, "type %" PRIx32));
}

TEST_F(TestWiresharkUtils, testValueStringValToStrConstFound) {
    EXPECT_STREQ("Two", val_to_str_const(2, test_vals, "missing"));
    EXPECT_STREQ("Eight", val_to_str_const(8, test_vals, "missing"));
}

TEST_F(TestWiresharkUtils, testValueStringValToStrConstNotfound) {
    EXPECT_STREQ("missing", val_to_str_const(0, test_vals, "missing"));
    EXPECT_STREQ("missing", val_to_str_const(3, test_vals, "missing"));
}
