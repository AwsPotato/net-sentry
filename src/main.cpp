#include <iostream>
#include <string>
#include <memory>
#include <chrono>
#include <limits>
#include <thread>
#include <vector>
#include <atomic>
#include <sstream>

// Defining macros required for Windows Npcap integration
#ifndef WPCAP
#define WPCAP
#endif
#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif
#include <pcap.h>
#include <winsock2.h>

#include <imgui.h>
#include <backends/imgui_impl_glfw.h>
#include <backends/imgui_impl_opengl3.h>
#include <GLFW/glfw3.h>
#include <implot.h>

#include "packet_utils.hpp"
#include "dns_tracker.hpp"
#include "game_telemetry.hpp"
#include "intrusion_detector.hpp"

// Global instances for modular components allowing zero-allocation passes
std::unique_ptr<DnsTracker> g_dns_tracker;
std::unique_ptr<GameTelemetry> g_game_telemetry;
std::unique_ptr<IntrusionDetector> g_intrusion_detector;

SharedTelemetryState g_telemetry_state;
std::atomic<bool> g_capture_running{false};
std::atomic<bool> g_shutdown_requested{false};
std::atomic<uint64_t> g_packet_count{0};
std::atomic<int> g_link_type{1}; // Default to 1 (DLT_EN10MB)
pcap_t* g_pcap_handle = nullptr;

void ApplyModernTheme() {
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 6.0f;
    style.FrameRounding = 6.0f;
    style.PopupRounding = 6.0f;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding = 6.0f;
    style.TabRounding = 6.0f;
    
    style.ItemSpacing = ImVec2(8.0f, 6.0f);
    style.WindowPadding = ImVec2(12.0f, 12.0f);
    
    ImVec4* colors = style.Colors;
    colors[ImGuiCol_Text] = ImVec4(0.95f, 0.96f, 0.98f, 1.00f);
    colors[ImGuiCol_TextDisabled] = ImVec4(0.36f, 0.42f, 0.47f, 1.00f);
    colors[ImGuiCol_WindowBg] = ImVec4(0.11f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.15f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.08f, 0.08f, 0.94f);
    colors[ImGuiCol_Border] = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg] = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.12f, 0.20f, 0.28f, 1.00f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.09f, 0.12f, 0.14f, 1.00f);
    colors[ImGuiCol_TitleBg] = ImVec4(0.09f, 0.12f, 0.14f, 0.65f);
    colors[ImGuiCol_TitleBgActive] = ImVec4(0.08f, 0.10f, 0.12f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 0.51f);
    colors[ImGuiCol_MenuBarBg] = ImVec4(0.15f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_ScrollbarBg] = ImVec4(0.02f, 0.02f, 0.02f, 0.39f);
    colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.18f, 0.22f, 0.25f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.09f, 0.21f, 0.31f, 1.00f);
    colors[ImGuiCol_CheckMark] = ImVec4(0.28f, 0.56f, 1.00f, 1.00f);
    colors[ImGuiCol_SliderGrab] = ImVec4(0.28f, 0.56f, 1.00f, 1.00f);
    colors[ImGuiCol_SliderGrabActive] = ImVec4(0.37f, 0.61f, 1.00f, 1.00f);
    colors[ImGuiCol_Button] = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.28f, 0.56f, 1.00f, 1.00f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.06f, 0.53f, 0.98f, 1.00f);
    colors[ImGuiCol_Header] = ImVec4(0.20f, 0.25f, 0.29f, 0.55f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.80f);
    colors[ImGuiCol_HeaderActive] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_Separator] = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_SeparatorHovered] = ImVec4(0.10f, 0.40f, 0.75f, 0.78f);
    colors[ImGuiCol_SeparatorActive] = ImVec4(0.10f, 0.40f, 0.75f, 1.00f);
    colors[ImGuiCol_ResizeGrip] = ImVec4(0.26f, 0.59f, 0.98f, 0.25f);
    colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
    colors[ImGuiCol_ResizeGripActive] = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);
    colors[ImGuiCol_Tab] = ImVec4(0.11f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_TabHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.80f);
    colors[ImGuiCol_TabActive] = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_TabUnfocused] = ImVec4(0.11f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.11f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_PlotLines] = ImVec4(0.61f, 0.61f, 0.61f, 1.00f);
    colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
    colors[ImGuiCol_PlotHistogram] = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
    colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
    colors[ImGuiCol_TextSelectedBg] = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
    colors[ImGuiCol_DragDropTarget] = ImVec4(1.00f, 1.00f, 0.00f, 0.90f);
    colors[ImGuiCol_NavHighlight] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.00f, 1.00f, 1.00f, 0.70f);
    colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.20f);
    colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.35f);
}

// Primary Packet Handler Callback
// Executed instantly by Npcap driver upon packet arrival
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (g_shutdown_requested) return;
    g_packet_count++;
    (void)user_data;
    auto arrival_time = std::chrono::high_resolution_clock::now();

    int offset = 14; // Default for DLT_EN10MB
    uint16_t ether_type = 0;
    if (g_link_type == 0) { // DLT_NULL (loopback)
        offset = 4;
        if (pkthdr->len < 4) return;
        uint32_t family = *reinterpret_cast<const uint32_t*>(packet);
        if (family == 2 || family == 0x02000000) {
            ether_type = 0x0800; // IPv4
        } else if (family == 23 || family == 24 || family == 28 || family == 0x1c000000) {
            ether_type = 0x86dd; // IPv6
        } else {
            return;
        }
    } else {
        // DLT_EN10MB
        if (pkthdr->len < 14) return;
        const struct sniff_ethernet* ethernet = reinterpret_cast<const struct sniff_ethernet*>(packet);
        ether_type = ntohs(ethernet->ether_type);
    }

    if (ether_type != 0x0800 && ether_type != 0x86dd) {
        return; // ignore non-IP
    }

    PacketMetadata meta{};
    meta.timestamp = arrival_time;

    int size_ip = 0;
    const u_char* payload = nullptr;
    int size_payload = 0;

    if (ether_type == 0x0800) {
        // IPv4
        if (pkthdr->len < static_cast<uint32_t>(offset + 20)) return;
        const struct sniff_ip* ip = reinterpret_cast<const struct sniff_ip*>(packet + offset);
        size_ip = IP_HL(ip) * 4;
        if (size_ip < 20 || pkthdr->len < static_cast<uint32_t>(offset + size_ip)) {
            return;
        }
        meta.src_ip = ip->ip_src.s_addr;
        meta.dst_ip = ip->ip_dst.s_addr;
        meta.protocol = ip->ip_p;
    } else {
        // IPv6
        if (pkthdr->len < static_cast<uint32_t>(offset + 40)) return;
        
        // Extract Next Header and skip any extension headers (Windows loopback/multicast often adds options)
        uint8_t next_header = packet[offset + 6];
        int ipv6_header_len = 40;
        
        while (next_header == 0 || next_header == 43 || next_header == 44 || next_header == 51 || next_header == 60) {
            if (static_cast<uint32_t>(offset + ipv6_header_len + 8) > pkthdr->len) {
                return; // Out of bounds
            }
            uint8_t ext_len = 0;
            if (next_header == 44) {
                ext_len = 8; // Fragment header is fixed at 8 bytes
            } else {
                ext_len = (packet[offset + ipv6_header_len + 1] + 1) * 8;
            }
            next_header = packet[offset + ipv6_header_len];
            ipv6_header_len += ext_len;
        }
        
        size_ip = ipv6_header_len;
        meta.src_ip = *reinterpret_cast<const uint32_t*>(packet + offset + 8 + 12); // last 4 bytes of IPv6 src
        meta.dst_ip = *reinterpret_cast<const uint32_t*>(packet + offset + 24 + 12); // last 4 bytes of IPv6 dst
        meta.protocol = next_header;
    }

    // ==========================================
    // 3. Unmap Transport Header (TCP/UDP)
    // ==========================================
    if (meta.protocol == IPPROTO_TCP) {
        // TCP Protocol
        if (pkthdr->len < static_cast<uint32_t>(offset + size_ip + 20)) return;
        const struct sniff_tcp* tcp = reinterpret_cast<const struct sniff_tcp*>(packet + offset + size_ip);
        int size_tcp = TH_OFF(tcp) * 4;
        
        if (size_tcp < 20 || pkthdr->len < static_cast<uint32_t>(offset + size_ip + size_tcp)) {
            return; // Invalid TCP length
        }

        meta.src_port = ntohs(tcp->th_sport);
        meta.dst_port = ntohs(tcp->th_dport);
        
        payload = packet + offset + size_ip + size_tcp;
        if (ether_type == 0x0800) {
            const struct sniff_ip* ip = reinterpret_cast<const struct sniff_ip*>(packet + offset);
            size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
        } else {
            size_payload = pkthdr->len - (offset + size_ip + size_tcp);
        }
        
    } else if (meta.protocol == IPPROTO_UDP) {
        // UDP Protocol
        if (pkthdr->len < static_cast<uint32_t>(offset + size_ip + 8)) return;
        const struct sniff_udp* udp = reinterpret_cast<const struct sniff_udp*>(packet + offset + size_ip);
        
        meta.src_port = ntohs(udp->uh_sport);
        meta.dst_port = ntohs(udp->uh_dport);
        

        payload = packet + offset + size_ip + 8;
        size_payload = ntohs(udp->uh_ulen) - 8;
    } else {
        // Unhandled protocol
        return;
    }

    meta.payload = payload;
    meta.payload_len = size_payload;

    // ==========================================
    // 4. Non-Blocking Modular Routing
    // ==========================================
    if (g_dns_tracker) g_dns_tracker->process(meta);
    if (g_game_telemetry) g_game_telemetry->process(meta);
    if (g_intrusion_detector) g_intrusion_detector->process(meta);
}

void capture_worker(const std::string& device_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_pcap_handle = pcap_open_live(device_name.c_str(), 65536, 1, 1000, errbuf);
    if (g_pcap_handle == nullptr) {
        std::cerr << "[!] Could not open device " << device_name << ": " << errbuf << "\n";
        g_capture_running = false;
        return;
    }

    g_link_type = pcap_datalink(g_pcap_handle);
    std::cout << "[+] Primary capture loop started on " << device_name << " (Link type: " << g_link_type << "). Listening for traffic...\n\n";
    g_capture_running = true;

    // Enter primary packet capture loop (Blocking until interrupted or error)
    pcap_loop(g_pcap_handle, 0, packet_handler, nullptr);

    // Shutdown Sequence
    if (g_pcap_handle) {
        pcap_close(g_pcap_handle);
        g_pcap_handle = nullptr;
    }
    std::cout << "[-] Capture session safely terminated.\n";
    g_capture_running = false;
}

int main() {
    std::cout << "=========================================\n";
    std::cout << " Net-Sentry - Unified Network Analyzer\n";
    std::cout << "=========================================\n";

    // Instantiate Modules (Smart Pointers)
    g_dns_tracker = std::make_unique<DnsTracker>();
    g_game_telemetry = std::make_unique<GameTelemetry>();
    g_intrusion_detector = std::make_unique<IntrusionDetector>();

    // Retrieve network interfaces
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == nullptr) {
        std::cerr << "[!] Error finding devices: " << errbuf << "\n";
        return 1;
    }

    struct NetAdapter {
        std::string name;
        std::string description;
    };
    std::vector<NetAdapter> adapters;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        adapters.push_back({d->name, d->description ? d->description : "No description"});
    }
    pcap_freealldevs(alldevs);

    // Initialize GLFW
    if (!glfwInit()) return 1;
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    GLFWwindow* window = glfwCreateWindow(1280, 720, "Net-Sentry Dashboard", nullptr, nullptr);
    if (!window) {
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    
    ImFont* mainFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 18.0f);
    (void)mainFont;
    ImFont* headerFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeb.ttf", 22.0f);

    ApplyModernTheme();

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    std::thread capture_thread;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("Main Dashboard", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);

        if (!g_capture_running) {
            ImVec2 size(700, 500);
            ImVec2 pos((io.DisplaySize.x - size.x) * 0.5f, (io.DisplaySize.y - size.y) * 0.5f);
            ImGui::SetCursorPos(pos);

            ImGui::BeginChild("Initialize Capture Engine", size, true, ImGuiWindowFlags_None);
            
            ImGui::Dummy(ImVec2(0.0f, 15.0f));
            if (headerFont) ImGui::PushFont(headerFont);
            ImGui::SetCursorPosX((size.x - ImGui::CalcTextSize("Select Network Adapter").x) * 0.5f);
            ImGui::Text("Select Network Adapter");
            if (headerFont) ImGui::PopFont();
            ImGui::Dummy(ImVec2(0.0f, 15.0f));
            ImGui::Separator();
            ImGui::Dummy(ImVec2(0.0f, 15.0f));

            if (ImGui::BeginChild("AdapterList", ImVec2(0, 0), false)) {
                for (size_t i = 0; i < adapters.size(); i++) {
                    ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x - 20.0f);
                    std::string label = adapters[i].description + "\n[" + adapters[i].name + "]";
                    if (ImGui::Button(label.c_str(), ImVec2(ImGui::GetContentRegionAvail().x, 60))) {
                        if (capture_thread.joinable()) {
                            capture_thread.join();
                        }
                        capture_thread = std::thread(capture_worker, adapters[i].name);
                        // Wait a tiny bit for thread to start so g_capture_running becomes true
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        break;
                    }
                    ImGui::PopTextWrapPos();
                    ImGui::Dummy(ImVec2(0.0f, 8.0f));
                }
            }
            ImGui::EndChild();
            ImGui::EndChild();
        } else {
            // Header showing active status and a Disconnect button
            ImGui::Text("Capturing from active adapter... Raw Packets Sniffed: %llu", g_packet_count.load());
            ImGui::SameLine();
            if (ImGui::Button("Stop Capture / Change Adapter")) {
                g_shutdown_requested = true;
                if (g_pcap_handle) {
                    pcap_breakloop(g_pcap_handle);
                }
                if (capture_thread.joinable()) {
                    capture_thread.join();
                }
                g_shutdown_requested = false;
                g_packet_count = 0;
                
                // Completely reset all telemetry data
                {
                    std::lock_guard<std::mutex> lock(g_telemetry_state.mtx);
                    g_telemetry_state.dns_events.clear();
                    g_telemetry_state.udp_jitter_history.clear();
                    g_telemetry_state.intrusion_alerts.clear();
                }
                
                // Reset analyzer states
                g_dns_tracker = std::make_unique<DnsTracker>();
                g_game_telemetry = std::make_unique<GameTelemetry>();
                g_intrusion_detector = std::make_unique<IntrusionDetector>();
                
                g_capture_running = false;
            }
            ImGui::Separator();

            // Dashboard Layout
            if (ImGui::BeginTable("DashboardTable", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_Borders)) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                
                // DNS Tracker
                ImGui::Text("DNS Request Feed");
                ImGui::SameLine();
                if (ImGui::Button("Copy All")) {
                    std::stringstream ss;
                    {
                        std::lock_guard<std::mutex> lock(g_telemetry_state.mtx);
                        for (auto it = g_telemetry_state.dns_events.rbegin(); it != g_telemetry_state.dns_events.rend(); ++it) {
                            ss << it->domain << "\n";
                        }
                    }
                    ImGui::SetClipboardText(ss.str().c_str());
                }
                
                static ImGuiTextFilter dns_filter;
                dns_filter.Draw("Filter##DNS", ImGui::GetContentRegionAvail().x);
                ImGui::Separator();
                if (ImGui::BeginChild("DNSFeed", ImVec2(0, ImGui::GetContentRegionAvail().y / 2), true)) {
                    std::lock_guard<std::mutex> lock(g_telemetry_state.mtx);
                    for (auto it = g_telemetry_state.dns_events.rbegin(); it != g_telemetry_state.dns_events.rend(); ++it) {
                        if (dns_filter.PassFilter(it->domain.c_str())) {
                            if (ImGui::Selectable(it->domain.c_str())) {
                                ImGui::SetClipboardText(it->domain.c_str());
                            }
                            if (ImGui::IsItemHovered()) {
                                ImGui::SetTooltip("Click to copy domain to clipboard");
                            }
                        }
                    }
                }
                ImGui::EndChild();

                // Intrusion Alerts
                ImGui::Text("Sentry Intrusion Alerts");
                ImGui::Separator();
                if (ImGui::BeginChild("IntrusionAlerts", ImVec2(0, 0), true)) {
                    std::lock_guard<std::mutex> lock(g_telemetry_state.mtx);
                    if (!g_telemetry_state.intrusion_alerts.empty()) {
                        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 50, 50, 255));
                        for (auto it = g_telemetry_state.intrusion_alerts.rbegin(); it != g_telemetry_state.intrusion_alerts.rend(); ++it) {
                            ImGui::Text("Port scan from %s (ports: %d)", it->ip.c_str(), it->port_count);
                            if (ImGui::IsItemHovered()) {
                                ImGui::SetTooltip("Targeted %d distinct ports recently", it->port_count);
                            }
                        }
                        ImGui::PopStyleColor();
                    } else {
                        ImGui::Text("No alerts detected.");
                    }
                }
                ImGui::EndChild();

                ImGui::TableSetColumnIndex(1);
                
                // Jitter Telemetry
                ImGui::Text("Live UDP Network Telemetry");
                ImGui::Separator();
                if (ImGui::BeginChild("JitterTelemetry", ImVec2(0, 0), true)) {
                    std::lock_guard<std::mutex> lock(g_telemetry_state.mtx);
                    if (!g_telemetry_state.udp_jitter_history.empty()) {
                        if (ImPlot::BeginPlot("##JitterPlot", ImVec2(-1, -1), ImPlotFlags_NoTitle | ImPlotFlags_NoLegend)) {
                            ImPlot::SetupAxes("Time", "Jitter (us)", ImPlotAxisFlags_AutoFit, ImPlotAxisFlags_AutoFit);
                            ImPlot::PlotLine("Jitter", g_telemetry_state.udp_jitter_history.data(), static_cast<int>(g_telemetry_state.udp_jitter_history.size()));
                            ImPlot::EndPlot();
                        }
                    } else {
                        ImGui::Text("Awaiting UDP telemetry...");
                    }
                }
                ImGui::EndChild();

                ImGui::EndTable();
            }
        }
        
        ImGui::End();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    g_shutdown_requested = true;
    if (g_pcap_handle) {
        pcap_breakloop(g_pcap_handle);
    }
    
    if (capture_thread.joinable()) {
        capture_thread.join();
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImPlot::DestroyContext();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
