#cmake_minimum_required(VERSION 2.8)

set(tester_SRCS
    tester.cc
)

add_executable(tester ${tester_SRCS})

target_link_libraries(tester 
    crypt util pthread rt nsl resolv m c dl ssl pcap dnet pcre restream decoder logger eventing)

set(CMAKE_CXX_FLAGS "-g -fvisibility=hidden -fno-strict-aliasing -Wall -fPIC -Wl,-E -fstack-protector -fno-strict-aliasing -pipe -fstack-protector -D_LARGEFILE_SOURCE")

include_directories(
    ../decoder
    ../restream
    ../logger
    ../eventing
    ../stats
    ../modeler
)
