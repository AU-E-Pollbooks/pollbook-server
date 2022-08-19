
add_library(openssl_wrapper OBJECT
    envelope_encryption.cpp
    envelope_key.cpp
    hash.cpp
    openssl_exception.cpp
    signature.cpp)
target_include_directories(openssl_wrapper PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

# OBJECT libraries are not linked, but this command can be used to declare library dependencies
target_link_libraries(openssl_wrapper OpenSSL::Crypto spdlog::spdlog)
