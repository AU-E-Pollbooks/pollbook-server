add_library(config OBJECT config.cpp)
target_include_directories(config PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
