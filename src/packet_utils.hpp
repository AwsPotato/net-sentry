#pragma once

#include <cstdint>
#include <winsock2.h> // For ntohs, ntohl, etc. (Windows)
#include <windows.h>
#include <chrono>

// Standard Ethernet header size
constexpr int ETHER_ADDR_LEN = 6;
constexpr int SIZE_ETHERNET = 14;

#pragma pack(push, 1) // Ensure 1-byte alignment for strict byte unmapping

// Ethernet header (14 bytes)
struct sniff_ethernet {
    uint8_t ether_dhost[ETHER_ADDR_LEN]; // Destination host address
    uint8_t ether_shost[ETHER_ADDR_LEN]; // Source host address
    uint16_t ether_type;                 // IP? ARP? RARP? etc
};

// IPv4 header (min 20 bytes)
struct sniff_ip {
    uint8_t ip_vhl;                 // Version (4 bits) + Header length (4 bits)
    uint8_t ip_tos;                 // Type of service
    uint16_t ip_len;                // Total length
    uint16_t ip_id;                 // Identification
    uint16_t ip_off;                // Fragment offset field
#define IP_RF 0x8000                // Reserved fragment flag
#define IP_DF 0x4000                // Don't fragment flag
#define IP_MF 0x2000                // More fragments flag
#define IP_OFFMASK 0x1fff           // Mask for fragmenting bits
    uint8_t ip_ttl;                 // Time to live
    uint8_t ip_p;                   // Protocol (TCP=6, UDP=17)
    uint16_t ip_sum;                // Checksum
    struct in_addr ip_src, ip_dst;  // Source and dest address
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

// TCP header (min 20 bytes)
struct sniff_tcp {
    uint16_t th_sport;      // Source port
    uint16_t th_dport;      // Destination port
    uint32_t th_seq;        // Sequence number
    uint32_t th_ack;        // Acknowledgement number
    uint8_t th_offx2;       // Data offset, rsvd
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
    uint16_t th_win;        // Window
    uint16_t th_sum;        // Checksum
    uint16_t th_urp;        // Urgent pointer
};

// UDP header (8 bytes)
struct sniff_udp {
    uint16_t uh_sport;      // Source port
    uint16_t uh_dport;      // Destination port
    uint16_t uh_ulen;       // UDP length
    uint16_t uh_sum;        // UDP checksum
};

#pragma pack(pop)

// Unified parsed metadata structure passed sequentially to modular handlers
struct PacketMetadata {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;       // 6 for TCP, 17 for UDP
    const uint8_t* payload; // Pointer to start of payload
    int payload_len;        // Length of payload in bytes
    std::chrono::high_resolution_clock::time_point timestamp;
};

#include <mutex>
#include <vector>
#include <string>

struct DnsEvent {
    std::chrono::high_resolution_clock::time_point timestamp;
    std::string domain;
};

struct IntrusionEvent {
    std::string ip;
    int port_count;
    std::chrono::high_resolution_clock::time_point time;
};

struct SharedTelemetryState {
    std::mutex mtx;
    std::vector<DnsEvent> dns_events;
    std::vector<float> udp_jitter_history; // Circular buffer for ImGui::PlotLines
    std::vector<IntrusionEvent> intrusion_alerts;
};

extern SharedTelemetryState g_telemetry_state;
