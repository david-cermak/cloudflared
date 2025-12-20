# ESP-IDF component - always use ESP32 HTTP client
idf_component_register(SRCS  "src/quick_tunnel.cpp"
                             "src/http_client_esp32.cpp"
                       INCLUDE_DIRS "include"
                       PRIV_REQUIRES esp_http_client cjson esp-tls)

# Enable C++ exceptions
target_compile_options(${COMPONENT_LIB} PRIVATE -fexceptions)