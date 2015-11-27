cmake_minimum_required(VERSION 2.8)

set(decoder_SRCS
    base_decoder.cc
    http.cc
    ssl.cc
    ssh.cc
)

add_library(decoder STATIC ${decoder_SRCS})

include_directories(../multifast)

add_definitions(-fPIC)

set(CMAKE_CXX_FLAGS "-g -Wall")

