cmake_minimum_required(VERSION 3.5)
project(vinatage2d)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES vintage2d.c)
include_directories(/usr/include/)
include_directories(/usr/src/linux-headers-3.13.0-36-generic/include/)
add_executable(vintage2d ${SOURCE_FILES})