set(TARGET_NAME plugin-test)

file(GLOB ALL_CPP *.cpp)
add_executable(${TARGET_NAME} ${ALL_CPP})
add_test(
    NAME ${TARGET_NAME}
    COMMAND ${TARGET_NAME}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
target_include_directories(${TARGET_NAME} PRIVATE ..)
target_link_libraries(${TARGET_NAME} PRIVATE tcpclv4 bpv7 wsutil)
target_link_libraries(${TARGET_NAME} PRIVATE GTest::GTest)
target_link_libraries(${TARGET_NAME} PRIVATE GTest::Main)
