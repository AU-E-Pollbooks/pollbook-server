# Create a "library" CMake target for all the source code
add_library(epollbook
    checkin_service.cpp
    pollbook_client.cpp
    log_utils.cpp
    voter_id_service.cpp
    $<TARGET_OBJECTS:config>
    $<TARGET_OBJECTS:openssl_wrapper>
    $<TARGET_OBJECTS:mutils-serialization>)

# Specify that the epollbook target needs the include directory in this project when building
target_include_directories(epollbook PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)

# Specify library dependencies for this target
target_link_libraries(epollbook
    mutils::mutils
    OpenSSL::Crypto
    spdlog::spdlog
    nlohmann_json::nlohmann_json)

# Set the C++ version for compiling this target (not really necessary if the global setting is used, but could help make the library more portable in the future)
target_compile_features(epollbook PUBLIC cxx_std_17)

# Configure the library to contain the same version number as the project
set_target_properties(epollbook PROPERTIES
    SOVERSION ${pollbook-server_VERSION_MAJOR}.${pollbook-server_VERSION_MINOR}
    VERSION ${pollbook-server_VERSION}
)
# Specify how to install this library (with "make install")
install(TARGETS epollbook EXPORT epollbookTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY
    include/
    TYPE INCLUDE)

set(ConfigPackageLocation ${CMAKE_INSTALL_LIBDIR}/cmake/epollbook)
# Use CMakePackageConfigHelpers to create a package version file and config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/cmake/epollbookConfigVersion.cmake"
    VERSION ${pollbook-server_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(${PROJECT_SOURCE_DIR}/cmake/epollbookConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/cmake/epollbookConfig.cmake"
    INSTALL_DESTINATION ${ConfigPackageLocation}
    PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_INCLUDEDIR
)

# Create a CMake "export file" for this library, to allow it to be imported as a dependency
install(EXPORT epollbookTargets
    FILE epollbookTargets.cmake
    NAMESPACE epollbook::
    DESTINATION ${ConfigPackageLocation}
)

