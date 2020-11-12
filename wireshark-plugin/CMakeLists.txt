cmake_policy(VERSION 3.10)
project(
    tcpcl 
    LANGUAGES C CXX
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

find_package(PkgConfig REQUIRED)

pkg_check_modules(WIRESHARK REQUIRED IMPORTED_TARGET wireshark>=2.6)
if(TARGET PkgConfig::WIRESHARK)
    set_target_properties(PkgConfig::WIRESHARK PROPERTIES
        INTERFACE_COMPILE_DEFINITIONS "HAVE_PLUGINS"
    )
endif()
if(NOT WIRESHARK_VERSION VERSION_LESS "3.0")
  set(WIRESHARK_APIVERS 3)
else()
  set(WIRESHARK_APIVERS 2)
endif()

pkg_get_variable(WIRESHARK_SYSTEM_PLUGINDIR wireshark plugindir)
set(INSTALL_MODULE_PATH "${WIRESHARK_SYSTEM_PLUGINDIR}/epan" CACHE FILEPATH "path to install the plugin module")

pkg_check_modules(GLIB2 glib-2.0)
pkg_check_modules(LIBGCRYPT libgcrypt)

find_package(GTest 1.6)

# Run tests with CTest
include(CTest)
enable_testing()

add_subdirectory(src)
