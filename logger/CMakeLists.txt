cmake_minimum_required(VERSION 2.8)

set(logger_SRCS
    log.cc
)

add_library(logger STATIC ${logger_SRCS})

add_definitions(-fPIC)

set(CMAKE_CXX_FLAGS "-g")

