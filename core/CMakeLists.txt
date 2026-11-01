cmake_minimum_required(VERSION 3.25)
project(SDPICore VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(WINDIVERT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../drivers/WinDivert")
set(WINDIVERT_INCLUDE_DIR "${WINDIVERT_ROOT}/include")
set(WINDIVERT_LIB_DIR "${WINDIVERT_ROOT}/x64")

if(NOT EXISTS "${WINDIVERT_INCLUDE_DIR}/windivert.h")
    message(FATAL_ERROR "windivert.h bulunamadi: ${WINDIVERT_INCLUDE_DIR}/windivert.h")
endif()
if(NOT EXISTS "${WINDIVERT_LIB_DIR}/WinDivert.lib")
    message(FATAL_ERROR "WinDivert.lib bulunamadi: ${WINDIVERT_LIB_DIR}/WinDivert.lib")
endif()

add_library(sdpi_core STATIC
    native/signature_verifier.cpp
    native/process_tracker.cpp
    native/packet_filter.cpp
    native/tls_parser.cpp
    native/dpi_engine.cpp
    native/flow_tracker.cpp
    native/socket_monitor.cpp
    native/windivert_manager.cpp
    native/ipc_server.cpp
    native/safety_manager.cpp
)

target_include_directories(sdpi_core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${WINDIVERT_INCLUDE_DIR}"
)

if(MSVC)
    target_compile_options(sdpi_core PUBLIC /W4 /EHsc /utf-8 /permissive-)
endif()

target_link_libraries(sdpi_core
    PUBLIC
        "${WINDIVERT_LIB_DIR}/WinDivert.lib"
        wintrust
        crypt32
        iphlpapi
        ws2_32
        advapi32
)

add_executable(sdpi-engine
    native/main.cpp
    native/sdpi.rc
)
target_link_libraries(sdpi-engine PRIVATE sdpi_core)

add_custom_command(TARGET sdpi-engine POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_SOURCE_DIR}/../engine"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:sdpi-engine>"
        "${CMAKE_CURRENT_SOURCE_DIR}/../engine/sdpi-engine.exe"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_LIB_DIR}/WinDivert.dll"
        "${CMAKE_CURRENT_SOURCE_DIR}/../engine/WinDivert.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_LIB_DIR}/WinDivert64.sys"
        "${CMAKE_CURRENT_SOURCE_DIR}/../engine/WinDivert64.sys"
    COMMENT "Motor ve surucu dosyalari engine/ dizinine kopyalaniyor"
)

add_executable(SDPI WIN32
    native/launcher.cpp
    native/sdpi.rc
)
target_link_libraries(SDPI PRIVATE shell32 user32)
add_custom_command(TARGET SDPI POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:SDPI>"
        "${CMAKE_CURRENT_SOURCE_DIR}/../SDPI.exe"
    COMMENT "SDPI.exe masaustu baslaticisi proje kok dizinine kopyalaniyor"
)
