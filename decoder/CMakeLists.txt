cmake_minimum_required(VERSION 2.8)

set(decoder_SRCS
    decoder.cc
)

add_library(decoder STATIC ${decoder_SRCS})

add_definitions(-fPIC)

set(CMAKE_CXX_FLAGS "-g")

