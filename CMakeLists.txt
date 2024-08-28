cmake_minimum_required(VERSION 3.19)

project(pollbook-server
    LANGUAGES CXX
    VERSION 1.0.0)

# Standard CMake setup
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
set(CMAKE_DISABLE_SOURCE_CHANGES ON)
include(GNUInstallDirs)

# Set the C++ version for the entire project
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Standard compiler option
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# System library dependencies
# Note: spdlog 1.11 introduced a breaking change that is not backward-compatible (due to fmt 9.1 introducing a breaking change)
find_package(spdlog 1.11 REQUIRED)
find_package(OpenSSL 3.0 REQUIRED)
find_path(ASIO_PATH asio.hpp) # Since ASIO doesn't export a CMake target, we have to find it manually

# Add nlohmann json
find_package(nlohmann_json 3.10.5 REQUIRED)

if(ASIO_PATH STREQUAL "ASIO_PATH-NOTFOUND")
    message(FATAL_ERROR "ASIO not found. You can download it from https://think-async.com/Asio")
endif()
include_directories(${ASIO_PATH})

# mutils library, which is required for mutils-serialization
find_package(mutils REQUIRED)

# Process CMakeLists from each source-code directory
add_subdirectory(src/config)
# add_subdirectory(src/mutils-serialization)
add_subdirectory(src/openssl)
add_subdirectory(src)
add_subdirectory(apps)
