cmake_minimum_required(VERSION 3.22.1)

project(meshopus CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# libopus is fetched at configure time and pinned by hash. The plan forbids local
# builds; CI is the only place this is compiled.
include(FetchContent)

set(OPUS_BUILD_SHARED_LIBRARY OFF CACHE BOOL "" FORCE)
set(OPUS_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(OPUS_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(OPUS_INSTALL_PKG_CONFIG_MODULE OFF CACHE BOOL "" FORCE)
set(OPUS_INSTALL_CMAKE_CONFIG_MODULE OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    opus
    URL "https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz"
    URL_HASH "SHA256=65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1"
)
FetchContent_MakeAvailable(opus)

add_library(meshopus SHARED opus_jni.cpp)
target_link_libraries(meshopus PRIVATE Opus::opus)
