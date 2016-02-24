project(ezfs)
cmake_minimum_required(VERSION 2.8)

if(WIN32)
    message(FATAL_ERROR "Windows is not supported yet.")
endif()

# compiler options
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic -Wall -std=c99")

# libraries
set(LIBRARIES)

# json
list(APPEND LIBRARIES json-c)
if(APPLE)
    include_directories(/usr/local/include/json-c)
else()
    include_directories(/usr/include/json-c)
endif()

# fuse
list(APPEND LIBRARIES fuse)
add_definitions(-DFUSE_USE_VERSION=29)
add_definitions(-D_FILE_OFFSET_BITS=64)
add_definitions(-D_POSIX_SOURCE)
add_definitions(-D_POSIX_C_SOURCE=200809L)
add_definitions(-D_XOPEN_SOURCE=700)
if(APPLE)
    include_directories(/usr/local/include/osxfuse)
    add_definitions(-D_DARWIN_USE_64_BIT_INODE)
endif()

add_executable(ezfs ezfs.c)
target_link_libraries(ezfs ${LIBRARIES})
