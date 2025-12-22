#include <stdio.h>
#include <string.h>
#include <string>
#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "quick_tunnel.h"
#include "dns_utils.h"

static const char *TAG = "QUICK_TUNNEL_MAIN";

namespace {

static void run_edge_srv_discovery_demo() {
    // Cloudflare edge discovery SRV name (same as Go):
    const char* srv_domain = "_v2-origintunneld._tcp.argotunnel.com";

    // For now use Cloudflare resolver directly over UDP.
    // (This mirrors the "direct resolver" approach and avoids relying on system DNS behavior.)
    const char* dns_server = "1.1.1.1";
    const uint16_t dns_port = 53;
    const int timeout_ms = 5000;

    ESP_LOGI(TAG, "Phase 2 demo: SRV lookup over UDP: %s (dns=%s:%u)", srv_domain, dns_server, dns_port);

    dns_utils_srv_record_t records[16];
    size_t record_count = 0;
    int rc = dns_utils_lookup_srv_udp(dns_server, dns_port, srv_domain, timeout_ms,
                                      records, sizeof(records) / sizeof(records[0]), &record_count);
    if (rc != 0 || record_count == 0) {
        ESP_LOGW(TAG, "SRV lookup failed rc=%d count=%d", rc, (int)record_count);
        return;
    }

    ESP_LOGI(TAG, "SRV answers: %d", (int)record_count);
    for (size_t i = 0; i < record_count; ++i) {
        const auto& r = records[i];
        ESP_LOGI(TAG, "SRV prio=%u weight=%u port=%u target=%s", r.priority, r.weight, r.port, r.target);

        char ips[16][DNS_UTILS_MAX_IP_STR];
        size_t ip_count = 0;
        int rcrc = dns_utils_resolve_host_ips(r.target, ips, 16, &ip_count);
        if (rcrc != 0 || ip_count == 0) {
            // Do not use gai_strerror; just log numeric error code.
            ESP_LOGW(TAG, "resolve_host_ips failed rc=%d target=%s", rcrc, r.target);
            continue;
        }
        for (size_t j = 0; j < ip_count; ++j) {
            ESP_LOGI(TAG, "  -> %s:%u", ips[j], r.port);
        }
    }
}

} // namespace

void printTunnelInfo(const QuickTunnelCredentials* creds) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "+--------------------------------------------------------------------------------------------+");
    ESP_LOGI(TAG, "|  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |");
    ESP_LOGI(TAG, "|  https://%s", creds->hostname.c_str());
    ESP_LOGI(TAG, "+--------------------------------------------------------------------------------------------+");
    ESP_LOGI(TAG, "");
    
    ESP_LOGI(TAG, "Tunnel ID: %s", creds->id.c_str());
    ESP_LOGI(TAG, "Account Tag: %s", creds->account_tag.c_str());
    ESP_LOGI(TAG, "Secret length: %zu bytes", creds->secret.size());
    
    // Print secret as hex for debugging (first 16 bytes)
    if (!creds->secret.empty()) {
        char hex_str[33] = {0}; // 16 bytes * 2 + null terminator
        size_t print_len = creds->secret.size() < 16 ? creds->secret.size() : 16;
        for (size_t i = 0; i < print_len; ++i) {
            sprintf(hex_str + (i * 2), "%02x", creds->secret[i]);
        }
        ESP_LOGI(TAG, "Secret (first %zu bytes, hex): %s", print_len, hex_str);
    }
}

void quick_tunnel_task(void *pvParameters)
{
    try {
        // Phase 2: edge discovery (DNS SRV lookup) demo
        run_edge_srv_discovery_demo();

        std::string quick_service = "https://api.trycloudflare.com";
        
        ESP_LOGI(TAG, "Requesting new quick Tunnel on %s...", quick_service.c_str());
        
        QuickTunnel tunnel(quick_service);
        QuickTunnelCredentials creds = tunnel.requestTunnel();
        
        printTunnelInfo(&creds);
        
        ESP_LOGI(TAG, "Quick tunnel request completed successfully.");
        ESP_LOGI(TAG, "Exiting (Phase 1.4 - tunnel request only).");
        
    } catch (const std::exception& e) {
        ESP_LOGE(TAG, "Error: %s", e.what());
    }
    
    vTaskDelete(NULL);
}

extern "C" void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());
    ESP_LOGI(TAG, "Connected to AP, begin quick tunnel example");

    xTaskCreate(&quick_tunnel_task, "quick_tunnel_task", 2*8192, NULL, 5, NULL);
}
