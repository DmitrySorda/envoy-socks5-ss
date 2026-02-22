cmake_minimum_required(VERSION 3.16)
project(envoy-socks5-filter VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(BUILD_TESTING "Build tests" ON)
option(BUILD_STANDALONE "Build standalone SOCKS5 library only (without Envoy)" ON)

# Compiler warnings
add_compile_options(
    -Wall -Wextra -Wpedantic
    -Werror=return-type
    -Wno-unused-parameter
)

# =============================================================================
# SOCKS5 Protocol Library (header-only)
# =============================================================================

add_library(socks5_lib INTERFACE)
target_include_directories(socks5_lib INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# =============================================================================
# Testing
# =============================================================================

if(BUILD_TESTING)
    enable_testing()
    
    # Try to find GTest
    find_package(GTest QUIET)
    
    if(GTest_FOUND)
        add_executable(socks5_test test/socks5_test.cc)
        target_link_libraries(socks5_test PRIVATE
            socks5_lib
            GTest::gtest
            GTest::gtest_main
        )
        
        include(GoogleTest)
        gtest_discover_tests(socks5_test)
    else()
        message(STATUS "GTest not found, skipping tests. Install with: brew install googletest")
    endif()
endif()

# =============================================================================
# Installation
# =============================================================================

include(GNUInstallDirs)

install(TARGETS socks5_lib
    EXPORT socks5-targets
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/socks5
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT socks5-targets
    FILE socks5-targets.cmake
    NAMESPACE socks5::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/socks5
)

# =============================================================================
# Package Config
# =============================================================================

include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/socks5-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/socks5-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/socks5
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/socks5-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/socks5-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/socks5-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/socks5
)

# =============================================================================
# Summary
# =============================================================================

message(STATUS "")
message(STATUS "=== envoy-socks5-filter Configuration ===")
message(STATUS "  Version:        ${PROJECT_VERSION}")
message(STATUS "  C++ Standard:   ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "  Build tests:    ${BUILD_TESTING}")
message(STATUS "  Standalone:     ${BUILD_STANDALONE}")
message(STATUS "")
