cmake_minimum_required(VERSION 3.20)
project(NetSentry VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Configure Npcap Include & Lib directories (Paths need to be adjusted by user based on installation)
# Standard location for Npcap SDK is C:/Npcap-SDK
set(NPCAP_DIR "C:/Npcap-SDK" CACHE PATH "Path to Npcap SDK")

include_directories(${NPCAP_DIR}/Include)
link_directories(${NPCAP_DIR}/Lib/x64)

# FetchContent for GLFW and ImGui
include(FetchContent)

FetchContent_Declare(
    glfw
    URL https://github.com/glfw/glfw/archive/refs/tags/3.4.zip
)
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(glfw)

FetchContent_Declare(
    imgui
    URL https://github.com/ocornut/imgui/archive/refs/heads/docking.zip
)
FetchContent_MakeAvailable(imgui)

# Setup ImGui library
set(IMGUI_DIR ${imgui_SOURCE_DIR})
add_library(imgui STATIC
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)
target_include_directories(imgui PUBLIC ${IMGUI_DIR} ${IMGUI_DIR}/backends)
target_link_libraries(imgui PUBLIC glfw opengl32)

# Create the main executable target
add_executable(NetSentry
    src/main.cpp
)

# Note: winsock2.h must be linked on Windows alongside wpcap and Packet
# We also link imgui, glfw, and opengl32 for the UI
target_link_libraries(NetSentry wpcap Packet ws2_32 imgui glfw opengl32)

# Optional: Add compiler warnings for cleaner production-grade code
if(MSVC)
    target_compile_options(NetSentry PRIVATE /W4 /WX)
else()
    target_compile_options(NetSentry PRIVATE -Wall -Wextra -Werror)
endif()
