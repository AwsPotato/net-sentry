#pragma once

#include "packet_utils.hpp"
#include <iostream>
#include <chrono>
#include <unordered_map>
#include <cmath>

class GameTelemetry {
public:
    GameTelemetry() {
        last_plot_update_ = std::chrono::high_resolution_clock::now();
    }

    void process(const PacketMetadata& meta) {
        // We track UDP packets typical for fast-paced game telemetry
        if (meta.protocol != 17) return;

        // Use a 64-bit pair of (src_ip, src_port) to track individual streams
        uint64_t stream_key = (static_cast<uint64_t>(meta.src_ip) << 32) | meta.src_port;

        auto now = meta.timestamp;
        
        auto it = last_arrival_.find(stream_key);
        if (it != last_arrival_.end()) {
            auto dt = std::chrono::duration_cast<std::chrono::microseconds>(now - it->second).count();
            
            // Track moving average of packet arrival interval
            double& avg_dt = avg_dt_[stream_key];
            if (avg_dt == 0.0) {
                avg_dt = static_cast<double>(dt);
            } else {
                avg_dt = 0.9 * avg_dt + 0.1 * dt;
            }

            // Calculate instantaneous jitter
            double current_jitter = std::abs(dt - avg_dt);
            
            // Maintain EWMA of jitter to smooth out outliers
            ewma_jitter_ = 0.95 * ewma_jitter_ + 0.05 * current_jitter;
            
            // Rate limit graph updates to 20Hz (50ms interval) to make the plot readable
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_plot_update_).count();
            if (elapsed >= 50) {
                std::lock_guard<std::mutex> lock(g_telemetry_state.mtx);
                g_telemetry_state.udp_jitter_history.push_back(static_cast<float>(ewma_jitter_));
                // Maintain fixed buffer size
                if (g_telemetry_state.udp_jitter_history.size() > 500) {
                    g_telemetry_state.udp_jitter_history.erase(g_telemetry_state.udp_jitter_history.begin());
                }
                last_plot_update_ = now;
            }
        }

        // Update the timestamp for the next packet calculation
        last_arrival_[stream_key] = now;
    }

private:
    std::unordered_map<uint64_t, std::chrono::high_resolution_clock::time_point> last_arrival_;
    std::unordered_map<uint64_t, double> avg_dt_;
    double ewma_jitter_ = 0.0;
    std::chrono::high_resolution_clock::time_point last_plot_update_;
};
