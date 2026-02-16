idf_component_register(SRCS "tunnel_main.c"
                            "quic_tunnel.c"
                            "control_stream.c"
                            "data_stream.c"
                            "http_proxy.c"
                            "capnp_minimal.c"
                       INCLUDE_DIRS "."
                       REQUIRES picoquic nvs_flash esp_event)
