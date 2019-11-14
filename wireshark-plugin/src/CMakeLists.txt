
add_library(tcpclv4 SHARED packet-tcpclv4.h packet-tcpclv4.c)
target_compile_definitions(tcpclv4 PRIVATE "WIRESHARK_APIVERS=${WIRESHARK_APIVERS}")
target_link_libraries(tcpclv4 PUBLIC PkgConfig::WIRESHARK)

add_library(bpv7 SHARED packet-bpv7.h packet-bpv7.c)
target_compile_definitions(bpv7 PRIVATE "WIRESHARK_APIVERS=${WIRESHARK_APIVERS}")
target_link_libraries(bpv7 PUBLIC PkgConfig::WIRESHARK)

if(INSTALL_MODULE_PATH)
    install(
        TARGETS tcpclv4 bpv7
        LIBRARY DESTINATION ${INSTALL_MODULE_PATH}
    )
endif(INSTALL_MODULE_PATH)

if (GTEST_FOUND)
    add_subdirectory(test)
endif()
