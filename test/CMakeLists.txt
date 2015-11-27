#cmake_minimum_required(VERSION 2.8)

set(tester_SRCS
    tester.cc
)

add_executable(tester ${tester_SRCS})

target_link_libraries(tester 
    crypt util pthread rt nsl resolv m c dl ssl pcap dnet pcre restream 
    logger eventing modeler stats decoder -L../multifast -lahocorasick)

set(CMAKE_CXX_FLAGS "-g -fvisibility=hidden -Wall -fPIC -Wl,-E -fno-strict-aliasing -pipe -fstack-protector")

include_directories(
    ../multifast
    ../decoder
    ../restream
    ../logger
    ../eventing
    ../stats
    ../modeler
)
