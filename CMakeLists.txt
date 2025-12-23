cmake_minimum_required(VERSION 3.15)
project(cpp-cloudflared VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CTest)

# Find required packages
find_package(PkgConfig REQUIRED)

# Try to find CURL - use manual detection if pkg-config fails
find_library(CURL_LIBRARY 
    NAMES curl libcurl
    PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
)

find_path(CURL_INCLUDE_DIR
    NAMES curl/curl.h
    PATHS /usr/include /usr/local/include
)

if(CURL_LIBRARY AND CURL_INCLUDE_DIR)
    set(CURL_FOUND TRUE)
    set(CURL_LIBRARIES ${CURL_LIBRARY})
    set(CURL_INCLUDE_DIRS ${CURL_INCLUDE_DIR})
    message(STATUS "Found CURL: ${CURL_LIBRARY}")
else()
    message(FATAL_ERROR "CURL not found. Please install libcurl development package (libcurl4-openssl-dev or libcurl4-gnutls-dev)")
endif()

# Find cJSON (may be in system or need to build from source)
pkg_check_modules(CJSON cJSON)
if(NOT CJSON_FOUND)
    message(STATUS "cJSON not found via pkg-config, will use bundled version")
    set(USE_BUNDLED_CJSON ON)
endif()

# Find OpenSSL (required for QUIC/TLS)
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
else()
    message(FATAL_ERROR "OpenSSL not found. Please install libssl-dev")
endif()

# Find ngtcp2 (QUIC library)
pkg_check_modules(NGTCP2 ngtcp2)
if(NOT NGTCP2_FOUND)
    # Try manual detection
    find_library(NGTCP2_LIBRARY
        NAMES ngtcp2 libngtcp2
        PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
    )
    find_path(NGTCP2_INCLUDE_DIR
        NAMES ngtcp2/ngtcp2.h
        PATHS /usr/include /usr/local/include
    )
    if(NGTCP2_LIBRARY AND NGTCP2_INCLUDE_DIR)
        set(NGTCP2_FOUND TRUE)
        set(NGTCP2_LIBRARIES ${NGTCP2_LIBRARY})
        set(NGTCP2_INCLUDE_DIRS ${NGTCP2_INCLUDE_DIR})
        message(STATUS "Found ngtcp2: ${NGTCP2_LIBRARY}")
    else()
        message(WARNING "ngtcp2 not found. QUIC functionality will not be available.")
        message(WARNING "Install ngtcp2: sudo apt-get install libngtcp2-dev (or build from source)")
        set(NGTCP2_FOUND FALSE)
    endif()
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/components/cloudflared/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/components/cloudflared/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/components/dns_utils/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party/cjson)

# Source files (using component sources)
set(SOURCES
    components/cloudflared/src/main.cpp
    components/cloudflared/src/quick_tunnel.cpp
    components/cloudflared/src/http_client_host.cpp
    components/cloudflared/src/edge_discovery.cpp
    components/dns_utils/src/dns_utils.cpp
)

set(HEADERS
    components/cloudflared/include/quick_tunnel.h
    components/cloudflared/include/http_client_host.h
    components/cloudflared/include/edge_discovery.h
    components/dns_utils/include/dns_utils.h
)

# Add QUIC client if ngtcp2 is available
if(NGTCP2_FOUND)
    list(APPEND SOURCES components/cloudflared/src/quic_client.cpp)
    list(APPEND HEADERS components/cloudflared/include/quic_client.h)
endif()

# Add executable
add_executable(cpp-cloudflared ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(cpp-cloudflared
    ${CURL_LIBRARIES}
    resolv
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_include_directories(cpp-cloudflared PRIVATE
    ${CURL_INCLUDE_DIRS}
)

# Add ngtcp2 if available
if(NGTCP2_FOUND)
    target_link_libraries(cpp-cloudflared ${NGTCP2_LIBRARIES})
    target_include_directories(cpp-cloudflared PRIVATE ${NGTCP2_INCLUDE_DIRS})
    target_compile_definitions(cpp-cloudflared PRIVATE NGTCP2_FOUND=1)
endif()

# If cJSON not found, add bundled version
if(USE_BUNDLED_CJSON)
    add_subdirectory(third_party/cjson)
    # cJSON creates library named "cjson" or "cjson-static" depending on build type
    # Try to find the correct library name
    if(TARGET cjson-static)
        target_link_libraries(cpp-cloudflared cjson-static)
    elseif(TARGET cjson)
        target_link_libraries(cpp-cloudflared cjson)
    else()
        message(FATAL_ERROR "cJSON library target not found")
    endif()
    target_include_directories(cpp-cloudflared PRIVATE third_party/cjson)
else()
    target_link_libraries(cpp-cloudflared ${CJSON_LIBRARIES})
    target_include_directories(cpp-cloudflared PRIVATE ${CJSON_INCLUDE_DIRS})
endif()

# Compiler options
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(cpp-cloudflared PRIVATE -Wall -Wextra -Wpedantic)
endif()

# -----------------------
# Tests (host only)
# -----------------------
if(BUILD_TESTING)
    add_executable(test_phase2_srv
        tests/test_phase2_srv.cpp
        components/dns_utils/src/dns_utils.cpp
    )
    target_include_directories(test_phase2_srv PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/components/dns_utils/include
    )
    target_link_libraries(test_phase2_srv resolv)
    add_test(NAME test_phase2_srv COMMAND test_phase2_srv)
endif()
