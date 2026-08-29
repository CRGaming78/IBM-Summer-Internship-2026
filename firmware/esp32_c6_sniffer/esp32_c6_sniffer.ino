#include <WiFi.h>
#include <esp_wifi.h>

String currentCommand = "";
int locked_channel = -1;

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return; // Only process management frames

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t *payload = pkt->payload;
    
    uint8_t frame_control = payload[0];
    uint8_t frame_subtype = (frame_control & 0xFC) >> 4;
    
    char src_mac[18], dst_mac[18], bssid[18];
    sprintf(dst_mac, "%02X:%02X:%02X:%02X:%02X:%02X", payload[4], payload[5], payload[6], payload[7], payload[8], payload[9]);
    sprintf(src_mac, "%02X:%02X:%02X:%02X:%02X:%02X", payload[10], payload[11], payload[12], payload[13], payload[14], payload[15]);
    sprintf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X", payload[16], payload[17], payload[18], payload[19], payload[20], payload[21]);

    int rssi = pkt->rx_ctrl.rssi;
    int channel = pkt->rx_ctrl.channel;
    
    String ftype = "other";
    if (frame_subtype == 8) ftype = "beacon";
    else if (frame_subtype == 4) ftype = "probe_req";
    else if (frame_subtype == 5) ftype = "probe_resp";
    else if (frame_subtype == 12) ftype = "deauth";
    else if (frame_subtype == 10) ftype = "disassoc";
    else if (frame_subtype == 11) ftype = "auth";
    else if (frame_subtype == 0) ftype = "assoc";
    
    if (ftype == "other") return;

    String ssid = "";
    if ((frame_subtype == 8 || frame_subtype == 5) && pkt->rx_ctrl.sig_len > 38) {
        uint8_t ssid_len = payload[37];
        if (ssid_len > 0 && ssid_len <= 32 && 38 + ssid_len < pkt->rx_ctrl.sig_len) {
            for(int i=0; i<ssid_len; i++) {
                char c = payload[38+i];
                if(c >= 32 && c <= 126) ssid += c; 
            }
        }
    }

    Serial.printf("{\"sensor_id\":\"esp32-c6\",\"band\":\"2.4GHz\",\"channel\":%d,\"frame_type\":\"%s\",\"src_mac\":\"%s\",\"dst_mac\":\"%s\",\"bssid\":\"%s\",\"ssid\":\"%s\",\"rssi\":%d}\n",
                  channel, ftype.c_str(), src_mac, dst_mac, bssid, ssid.c_str(), rssi);
}

void setup() {
    Serial.begin(115200);
    delay(2000); // Give Serial time to attach and stabilize USB-CDC
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    Serial.println("{\"status\":\"c6_ready\"}");
}

void loop() {
    if (Serial.available()) {
        char c = Serial.read();
        if (c == '\n') {
            if (currentCommand.equals("CMD_PING")) {
                Serial.println("{\"status\":\"c6_ready\"}");
            }
            else if (currentCommand.startsWith("CMD_LOCK:")) {
                locked_channel = currentCommand.substring(9).toInt();
                if (locked_channel >= 1 && locked_channel <= 14) {
                    esp_wifi_set_promiscuous(false);
                    esp_wifi_set_channel(locked_channel, WIFI_SECOND_CHAN_NONE);
                    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
                    esp_wifi_set_promiscuous(true);
                    Serial.printf("{\"status\":\"locked\",\"channel\":%d}\n", locked_channel);
                }
            }
            currentCommand = "";
        } else {
            currentCommand += c;
        }
    }
}
