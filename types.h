// Header File: types.h
#ifndef TYPES_H
#define TYPES_H

// Include the ESP-IDF Wi-Fi types header where wifi_promiscuous_filter_t
// and the WIFI_PROMIS_FILTER_MASK_ macros are defined.
// This is CRUCIAL to fix the "unknown type name" errors.
#include <esp_wifi.h> // <-- THIS LINE IS NECESSARY

// --- Custom Structure Definitions ---
// These were provided in your snippets

typedef struct {
  // Frame Control field (2 bytes) - 0xC000 is the Type/Subtype for Deauthentication
  uint8_t frame_control[2] = { 0xC0, 0x00 };
  uint8_t duration[2];     // Duration field (2 bytes)
  uint8_t station[6];      // Destination MAC Address (the station to deauthenticate)
  uint8_t sender[6];       // Source MAC Address (the AP's MAC)
  uint8_t access_point[6]; // BSSID (the AP's MAC)
  // Fragment number (lower 4 bits) and Sequence number (upper 12 bits)
  // The values 0xF0, 0xFF give sequence 4095, fragment 0. You might need to manage this.
  uint8_t fragment_sequence[2] = { 0xF0, 0xFF }; // This might be incorrectly structured. Usually, sequence is 12 bits, fragment is 4 bits. A uint16_t might be better.
  uint16_t reason;         // Reason Code (2 bytes)
} deauth_frame_t;

typedef struct {
  uint16_t frame_ctrl;    // Frame Control (2 bytes)
  uint16_t duration;      // Duration/ID (2 bytes)
  uint8_t dest[6];        // Address 1 (Destination MAC)
  uint8_t src[6];         // Address 2 (Source MAC)
  uint8_t bssid[6];       // Address 3 (BSSID)
  uint16_t sequence_ctrl; // Sequence Control (2 bytes) - Sequence number (12 bits) + Fragment number (4 bits)
  uint8_t addr4[6];       // Address 4 (only in WDS) - Note: Your sniffer code doesn't seem to handle addr4 explicitly.
} mac_hdr_t;

// Structure representing a standard Wi-Fi packet payload following the MAC header
// The payload[0] is a flexible array member, meaning the actual data follows after the header.
typedef struct {
  mac_hdr_t hdr;
  uint8_t payload[0]; // Flexible array member (requires C99 or later)
} wifi_packet_t;

// Structure provided by esp_wifi.h for configuring the promiscuous mode filter
// This requires esp_wifi.h to be included BEFORE this definition.
const wifi_promiscuous_filter_t filt = {
  .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA // Filter for Management and Data frames
};

// --- Add any other necessary definitions or declarations from your original types.h ---
// e.g., wifi_promiscuous_pkt_t structure if your version differs from esp_wifi.h's

#endif // TYPES_H
