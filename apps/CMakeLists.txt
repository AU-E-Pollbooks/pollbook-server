# This file builds the finished executables for the client and server

# Allow any target in this directory to include header files within the same directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Create the "server" executable and link it to the library containing the rest of the code
add_executable(server server.cpp)
target_link_libraries(server epollbook nlohmann_json::nlohmann_json)
target_compile_features(server PUBLIC cxx_std_17)

# Same procedure with the "client" executable
add_executable(client client.cpp)
target_link_libraries(client epollbook nlohmann_json::nlohmann_json)
target_compile_features(client PUBLIC cxx_std_17)

add_executable(secure_client secure_client.cpp)
target_link_libraries(secure_client epollbook nlohmann_json::nlohmann_json)
target_compile_features(secure_client PUBLIC cxx_std_17)

add_executable(warning_cache_client warning_cache_client.cpp)
target_link_libraries(warning_cache_client epollbook nlohmann_json::nlohmann_json)
target_compile_features(warning_cache_client PUBLIC cxx_std_17)

add_executable(id_server id_server.cpp)
target_link_libraries(id_server epollbook nlohmann_json::nlohmann_json)
target_compile_features(id_server PUBLIC cxx_std_17)
file(GLOB PY_FILES "${CMAKE_SOURCE_DIR}/tests/clients/*.py")

add_custom_target(copy_python_files ALL
    COMMAND ${CMAKE_COMMAND} -E copy ${PY_FILES} ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Copy Python files to build/apps/"
)


add_custom_command(TARGET server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/local-test-deployment ${CMAKE_CURRENT_BINARY_DIR}/local-test-deployment
    DEPENDS client secure_client id_server
    COMMENT "Copy local-test-deployment config files"
    VERBATIM)

add_custom_command(TARGET server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/docker-test-deployment ${CMAKE_CURRENT_BINARY_DIR}/docker-test-deployment
    DEPENDS client secure_client id_server
    COMMENT "Copy docker-test-deployment config files"
    VERBATIM)
