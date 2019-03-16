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

file(GLOB ALL_H src/*.h)
file(GLOB ALL_C src/*.c)
add_library(tcpcl MODULE ${ALL_H} ${ALL_C})
target_compile_definitions(tcpcl PRIVATE -DHAVE_PLUGINS)
target_include_directories(tcpcl PUBLIC ${WIRESHARK_INCLUDE_DIRS})
target_link_libraries(tcpcl PUBLIC ${WIRESHARK_LINK_LIBRARIES})
if(INSTALL_MODULE_PATH)
    install(
        TARGETS tcpcl
        LIBRARY DESTINATION ${INSTALL_MODULE_PATH}
    )
endif(INSTALL_MODULE_PATH)
