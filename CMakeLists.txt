cmake_minimum_required(VERSION 2.8)

#set(USE_DEBUG $ENV{USE_DEBUG})

add_subdirectory(decoder)
add_subdirectory(restream)
add_subdirectory(logger)
add_subdirectory(eventing)
add_subdirectory(stats)
add_subdirectory(modeler)
add_subdirectory(test)
