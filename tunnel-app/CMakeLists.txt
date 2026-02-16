cmake_minimum_required(VERSION 3.16)

# pquic picoquic component (relative to this project directory)
set(EXTRA_COMPONENT_DIRS "../../pquic/picoquic")
if("${IDF_TARGET}" STREQUAL "linux")
    list(APPEND EXTRA_COMPONENT_DIRS
         "../../pquic/deps/esp-protocols/common_components/linux_compat")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
project(cloudflare-tunnel)
