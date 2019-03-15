cmake_policy(VERSION 3.10)
project(
    tcpcl 
    LANGUAGES C
    VERSION 0.0
)
cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_STANDARD 11)
option(CMAKE_BUILD_TYPE "Build type" "RelWithDebInfo")
if(MSVC)
  add_compile_options(/W4 /WX)
else(MSVC)
  add_compile_options(-Wall -Wextra -pedantic -Werror)
endif(MSVC)

find_package(PkgConfig)
pkg_check_modules(WIRESHARK REQUIRED wireshark)

file(GLOB ALL_C src/*.c)
add_library(tcpcl MODULE ${ALL_C})
target_compile_definitions(tcpcl PRIVATE -DHAVE_PLUGINS)
target_include_directories(tcpcl PUBLIC ${WIRESHARK_INCLUDE_DIRS})
target_link_libraries(tcpcl PUBLIC ${WIRESHARK_LINK_LIBRARIES})
if(INSTALL_MODULE_PATH)
    install(
        TARGETS tcpcl
        LIBRARY DESTINATION ${INSTALL_MODULE_PATH}
    )
endif(INSTALL_MODULE_PATH)
