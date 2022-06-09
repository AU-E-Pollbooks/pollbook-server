# This file builds the finished executables for the client and server

# Allow any target in this directory to include header files within the same directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Create the "server" executable and link it to the library containing the rest of the code
add_executable(server server.cpp)
target_link_libraries(server epollbook)
target_compile_features(server PUBLIC cxx_std_17)

# Same procedure with the "client" executable
add_executable(client client.cpp)
target_link_libraries(client epollbook)
target_compile_features(client PUBLIC cxx_std_17)