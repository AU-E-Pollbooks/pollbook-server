set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
project (mutils-serialization)

add_library(mutils-serialization OBJECT SerializationSupport.cpp)
target_include_directories(mutils-serialization PRIVATE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)
target_link_libraries(mutils-serialization mutils::mutils)

add_executable(serialization-test serialization-test.cpp)
target_link_libraries(serialization-test mutils-serialization nlohmann_json::nlohmann_json)
target_include_directories(serialization-test PRIVATE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)
