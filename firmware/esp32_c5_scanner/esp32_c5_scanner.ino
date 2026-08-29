#include <WiFi.h>
#include <esp_wifi.h>

const int ANTENNA_PIN = 26;
String currentCommand = "";
bool hopping_mode = false;
int hop_channels[20];
int num_hop_channels = 0;
int current_hop_idx = 0;
unsigned long last_hop_time = 0;
const int HOP_INTERVAL_MS = 150;

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
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

    String band = (channel > 14) ? "5GHz" : "2.4GHz";

    Serial.printf("{\"sensor_id\":\"esp32-c5\",\"band\":\"%s\",\"channel\":%d,\"frame_type\":\"%s\",\"src_mac\":\"%s\",\"dst_mac\":\"%s\",\"bssid\":\"%s\",\"ssid\":\"%s\",\"rssi\":%d}\n",
                  band.c_str(), channel, ftype.c_str(), src_mac, dst_mac, bssid, ssid.c_str(), rssi);
}

void perform_scan() {
    esp_wifi_set_promiscuous(false);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    int n = WiFi.scanNetworks(false, true); // (async=false, show_hidden=true)
    Serial.println("{\"status\":\"scan_results\", \"networks\": [");
    for (int i = 0; i < n; ++i) {
        String ssid = WiFi.SSID(i);
        String bssid = WiFi.BSSIDstr(i);
        int32_t rssi = WiFi.RSSI(i);
        int32_t channel = WiFi.channel(i);
        String enc = (WiFi.encryptionType(i) == WIFI_AUTH_OPEN) ? "open" : "secured";
        
        Serial.printf("  {\"ssid\":\"%s\",\"bssid\":\"%s\",\"channel\":%d,\"rssi\":%d,\"encryption\":\"%s\"}", 
                      ssid.c_str(), bssid.c_str(), channel, rssi, enc.c_str());
        if (i < n - 1) Serial.println(",");
        else Serial.println("");
    }
    Serial.println("]}");
}

void parse_hop_channels(String cmd) {
    String channels_str = cmd.substring(8);
    num_hop_channels = 0;
    int start = 0;
    while(start < channels_str.length() && num_hop_channels < 20) {
        int idx = channels_str.indexOf(',', start);
        if (idx == -1) {
            hop_channels[num_hop_channels++] = channels_str.substring(start).toInt();
            break;
        } else {
            hop_channels[num_hop_channels++] = channels_str.substring(start, idx).toInt();
            start = idx + 1;
        }
    }
}

void setup() {
    Serial.begin(115200);
    delay(2000); // Give Serial time to attach and stabilize USB-CDC
    pinMode(ANTENNA_PIN, OUTPUT);
    digitalWrite(ANTENNA_PIN, LOW); // LOW = Internal PCB Antenna (Emergency Fix), HIGH = External U.FL Antenna
    delay(10);
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    Serial.println("{\"status\":\"c5_ready\"}");
}

void loop() {
    if (Serial.available()) {
        char c = Serial.read();
        if (c == '\n') {
            if (currentCommand.equals("CMD_SCAN")) {
                hopping_mode = false;
                perform_scan();
            } 
            else if (currentCommand.equals("CMD_PING")) {
                Serial.println("{\"status\":\"c5_ready\"}");
            }
            else if (currentCommand.startsWith("CMD_HOP:")) {
                parse_hop_channels(currentCommand);
                if (num_hop_channels > 0) {
                    WiFi.mode(WIFI_STA); 
                    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
                    esp_wifi_set_promiscuous(true);
                    hopping_mode = true;
                    current_hop_idx = 0;
                    last_hop_time = millis();
                    Serial.printf("{\"status\":\"hopping_started\",\"count\":%d}\n", num_hop_channels);
                }
            }
            currentCommand = "";
        } else {
            currentCommand += c;
        }
    }

    if (hopping_mode && num_hop_channels > 0) {
        if (millis() - last_hop_time > HOP_INTERVAL_MS) {
            last_hop_time = millis();
            int ch = hop_channels[current_hop_idx];
            
            // Depending on the core version, setting 5GHz band may require a specific call:
            // esp_wifi_set_band(WIFI_BAND_5G); 
            // In many recent implementations, esp_wifi_set_channel dynamically adjusts the band if ch > 14
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            
            current_hop_idx = (current_hop_idx + 1) % num_hop_channels;
        }
    }
}
