set(TARGET_NAME plugin-test)

file(GLOB ALL_CPP *.cpp)
add_executable(${TARGET_NAME} ${ALL_CPP})
add_test(${TARGET_NAME} ${TARGET_NAME})
#gtest_add_tests(
#    TARGET ${TARGET_NAME}
#    TEST_LIST ALL_TESTS
#)
target_include_directories(${TARGET_NAME} PRIVATE ..)
target_link_libraries(${TARGET_NAME} PRIVATE tcpclv4 bpv7 wsutil)

target_link_libraries(${TARGET_NAME} PRIVATE ${GTEST_LIBRARIES})
target_link_libraries(${TARGET_NAME} PRIVATE ${GTEST_MAIN_LIBRARIES})
