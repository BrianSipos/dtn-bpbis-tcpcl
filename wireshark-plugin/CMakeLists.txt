cmake_policy(VERSION 3.10)
project(
    tcpcl 
    LANGUAGES C
    VERSION 0.0
)
cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_STANDARD 11)
set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type")
if(MSVC)
  add_compile_options(/W4 /WX)
else(MSVC)
  add_compile_options(-Wall -Wextra -pedantic -Werror)
endif(MSVC)

find_package(PkgConfig)

pkg_check_modules(WIRESHARK REQUIRED wireshark>=2.6)
pkg_get_variable(WIRESHARK_SYSTEM_PLUGINDIR wireshark plugindir)
set(INSTALL_MODULE_PATH "${WIRESHARK_SYSTEM_PLUGINDIR}/epan" CACHE FILEPATH "path to install the plugin module")

pkg_check_modules(LIBCBOR REQUIRED libcbor>=0.5)


add_library(tcpclv4 MODULE src/packet-tcpclv4.h src/packet-tcpclv4.c)
target_compile_definitions(tcpclv4 PRIVATE -DHAVE_PLUGINS)
target_include_directories(tcpclv4 PUBLIC ${WIRESHARK_INCLUDE_DIRS})
target_link_libraries(tcpclv4 PUBLIC ${WIRESHARK_LINK_LIBRARIES})

add_library(bpv7 MODULE src/packet-bpv7.h src/packet-bpv7.c)
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
