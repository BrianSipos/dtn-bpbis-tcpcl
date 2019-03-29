
add_library(tcpclv4 SHARED packet-tcpclv4.h packet-tcpclv4.c)
target_compile_definitions(tcpclv4 PRIVATE -DHAVE_PLUGINS)
target_include_directories(tcpclv4 PUBLIC ${WIRESHARK_INCLUDE_DIRS})
target_link_libraries(tcpclv4 PUBLIC ${WIRESHARK_LINK_LIBRARIES})

add_library(bpv7 SHARED packet-bpv7.h packet-bpv7.c)
target_compile_definitions(bpv7 PRIVATE -DHAVE_PLUGINS)
target_include_directories(bpv7 PUBLIC ${WIRESHARK_INCLUDE_DIRS})
target_link_libraries(bpv7 PUBLIC ${WIRESHARK_LIBRARIES})
target_include_directories(bpv7 PUBLIC ${LIBCBOR_INCLUDE_DIRS})
target_link_libraries(bpv7 PUBLIC ${LIBCBOR_LIBRARIES})

if(INSTALL_MODULE_PATH)
    install(
        TARGETS tcpclv4 bpv7
        LIBRARY DESTINATION ${INSTALL_MODULE_PATH}
    )
endif(INSTALL_MODULE_PATH)

if (GTEST_FOUND)
    add_subdirectory(test)
endif()
