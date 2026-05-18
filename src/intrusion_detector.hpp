#pragma once

#include "packet_utils.hpp"
#include <ws2tcpip.h>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <string>

class IntrusionDetector {
public:
    void process(const PacketMetadata& meta) {
        // Track incoming connections mapped by Source IP
        uint32_t src_ip = meta.src_ip;
        uint16_t dst_port = meta.dst_port;

        auto now = meta.timestamp;
        auto& record = scan_records_[src_ip];
        
        // Clean up old tracked records (e.g., reset the scan window every 5 seconds)
        if (std::chrono::duration_cast<std::chrono::seconds>(now - record.first_seen).count() > 5) {
            record.scanned_ports.clear();
            record.first_seen = now;
        }

        if (record.scanned_ports.empty()) {
            record.first_seen = now;
        }

        // Insert new port into the set (ignoring duplicates)
        record.scanned_ports.insert(dst_port);

        // Heuristic: Alert if a rapid multi-port scan is detected (e.g., > 10 distinct ports within 5 seconds)
        if (record.scanned_ports.size() > 10) {
            std::lock_guard<std::mutex> lock(g_telemetry_state.mtx);
            g_telemetry_state.intrusion_alerts.push_back({ip_to_string(src_ip), static_cast<int>(record.scanned_ports.size()), now});
            
            // Clear to avoid spamming for the same ongoing scan
            record.scanned_ports.clear();
        }
    }

private:
    struct ScanRecord {
        std::unordered_set<uint16_t> scanned_ports;
        std::chrono::high_resolution_clock::time_point first_seen;
    };

    std::unordered_map<uint32_t, ScanRecord> scan_records_;

    // Helper to stringify an IPv4 integer to a readable string (e.g. 192.168.1.1)
    std::string ip_to_string(uint32_t ip) {
        struct in_addr addr;
        addr.s_addr = ip;
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
            return std::string(buf);
        }
        return "invalid";
    }
};
