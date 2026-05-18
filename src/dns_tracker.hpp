#pragma once

#include "packet_utils.hpp"
#include <iostream>
#include <string>
#include <cctype>
#include <algorithm>
#include <cstdio>

class DnsTracker {
public:
    void process(const PacketMetadata& meta) {
        if (meta.src_port == 53 || meta.dst_port == 53) {
            std::cout << "[DEBUG PROCESS] DNS Packet. Proto: " << (int)meta.protocol 
                      << ", PayloadLen: " << meta.payload_len << "\n";
            
            // Print raw hex of first 32 bytes of the payload
            std::cout << "  Raw Payload (hex): ";
            int print_len = (meta.payload_len < 32 ? meta.payload_len : 32);
            for (int i = 0; i < print_len; ++i) {
                printf("%02X ", meta.payload[i]);
            }
            std::cout << "\n  Raw Payload (ascii): ";
            for (int i = 0; i < print_len; ++i) {
                char c = static_cast<char>(meta.payload[i]);
                if (c >= 32 && c <= 126) std::cout << c;
                else std::cout << ".";
            }
            std::cout << "\n";
        }

        // Only process UDP packets on port 53 (DNS)
        if (meta.protocol != 17) return;
        if (meta.src_port != 53 && meta.dst_port != 53) return;

        // DNS header is 12 bytes long, payload needs to be larger to contain queries
        if (meta.payload_len <= 12) {
            if (meta.src_port == 53 || meta.dst_port == 53) {
                std::cout << "  [DEBUG PROCESS] Bailing out because payload_len <= 12\n";
            }
            return; 
        }

        // Basic DNS parsing logic:
        // Skip 12-byte DNS header to reach the Questions section
        const uint8_t* dns_data = meta.payload + 12;
        int remaining = meta.payload_len - 12;

        std::string query_name = extract_dns_name(dns_data, remaining);
        if (meta.src_port == 53 || meta.dst_port == 53) {
            std::cout << "[DEBUG PROCESS] Extracted QNAME: '" << query_name << "'\n";
        }
        
        if (!query_name.empty()) {
            std::lock_guard<std::mutex> lock(g_telemetry_state.mtx);
            g_telemetry_state.dns_events.push_back({meta.timestamp, query_name});
        }
    }

private:
    std::string extract_dns_name(const uint8_t* data, int max_len) {
        std::string name;
        int pos = 0;
        
        while (pos < max_len) {
            int len = data[pos];
            if (len == 0) break; // Null byte indicates end of the string
            
            // Handle DNS pointer (compression) - checking top 2 bits
            if ((len & 0xC0) == 0xC0) {
                // To keep this lightweight, we simply stop tracking upon hitting a compressed pointer.
                // In a robust implementation, this pointer refers to a prior offset in the packet payload.
                break; 
            }

            pos++; // Move past length byte
            if (pos + len > max_len) break;

            for (int i = 0; i < len; ++i) {
                uint8_t val = data[pos + i];
                if (val >= 32 && val <= 126) {
                    name += static_cast<char>(val);
                } else {
                    name += '.';
                }
            }
            name += '.';
            pos += len;
        }

        if (!name.empty() && name.back() == '.') {
            name.pop_back(); // Clean up trailing dot
        }
        return name;
    }
};