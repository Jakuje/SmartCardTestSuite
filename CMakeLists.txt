cmake_minimum_required(VERSION 3.3)
project(SmartCardTestSuite)

include_directories(${PROJECT_SOURCE_DIR}/libs)
link_directories(${PROJECT_SOURCE_DIR}/libs)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake/Modules/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)
#message("Output dir is ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wdeprecated-declarations")
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g -DNDEBUG")
set(SOURCE_FILES test_suits.c loader.h loader.c test_suits.h common.h test_helpers.h test_helpers.c common.c)

add_executable(SmartCardTestSuite ${SOURCE_FILES})

find_package(CMocka REQUIRED)
target_include_directories(SmartCardTestSuite PUBLIC ${CMOCKA_INCLUDE_DIR})
target_link_libraries(SmartCardTestSuite ${CMOCKA_LIBRARIES} -ldl)


