# SPDX-FileCopyrightText: Copyright 2025 Yamane Kazuma
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION "3.20")

include(FetchContent)

set(LIBPEIO_VERSION_MAJOR 0)
set(LIBPEIO_VERSION_MINOR 1)
set(LIBPEIO_VERSION_PATCH 0)

project(libpeio VERSION ${LIBPEIO_VERSION_MAJOR}.${LIBPEIO_VERSION_MINOR}.${LIBPEIO_VERSION_PATCH} LANGUAGES CXX)

# ==== Config ====

option(LIBPEIO_BUILD_ALL "Build all artifacts" OFF)

option(LIBPEIO_BUILD_EXAMPLE "Build example" ON)
option(LIBPEIO_BUILD_EXAMPLE_HO "Build example using header only version" ON)

option(LIBPEIO_BUILD_TESTS "Build tests" OFF)
option(LIBPEIO_BUILD_TESTS_HO "Build tests for header only version" OFF)

# ================

set(LIBPEIO_SOURCES "include/peio/impl/peio.cpp")
set(LIBPEIO_HEADERS "include/peio/peio.h")

add_library(libpeio ${LIBPEIO_SOURCES})
add_library(libpeio::libpeio ALIAS libpeio)

target_compile_features(libpeio PUBLIC cxx_std_23)

target_include_directories(libpeio PUBLIC include/)

target_compile_definitions(
  libpeio
  PUBLIC
  $<$<CONFIG:Debug>:
    _DEBUG
    DEBUG
  >
)

if(MSVC)
  set_property(TARGET libpeio PROPERTY MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug>:EditAndContinue>")
  target_compile_options(
    libpeio
    PUBLIC
    /W4 /arch:AVX /fp:fast /GS /GT /MP /nologo /Oi /Qpar /utf-8
    $<$<CONFIG:Debug>:/JMC /LDd /Ob0 /Od /RTC1>
    $<$<CONFIG:Release>:/GA /GL /Gy /guard:cf- /LD /Os>
  )
  if(CMAKE_CXX_FLAGS MATCHES "/W3")
    STRING(REPLACE "/W3" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  endif(CMAKE_CXX_FLAGS MATCHES "/W3")
  if(CMAKE_CXX_FLAGS MATCHES "/GR")
    STRING(REPLACE "/GR" "/GR-" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  else(CMAKE_CXX_FLAGS MATCHES "/GR")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GR-")
  endif(CMAKE_CXX_FLAGS MATCHES "/GR")
else(MSVC)
  target_compile_options(
    libpeio
    PUBLIC
    -Wall -Wextra -mavx -mfpmath=sse
    -finput-charset=UTF-8 -fexec-charset=UTF-8 -municode
    $<$<CONFIG:Debug>:-Og -g>
    $<$<CONFIG:Release>:-O3 -ftree-vectorize -fomit-frame-pointer>
  )
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # for x64
    target_compile_options(libpeio PUBLIC -m64)
  else(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # for x86
    target_compile_options(libpeio PUBLIC -m32)
  endif(CMAKE_SIZEOF_VOID_P EQUAL 8)
endif(MSVC)


FetchContent_Declare(
  mio
  GIT_REPOSITORY https://github.com/vimpunk/mio.git
  GIT_TAG master
)
FetchContent_MakeAvailable(mio)
target_link_libraries(libpeio PUBLIC mio::mio)

# Define for header only version

add_library(libpeio_header_only INTERFACE)
add_library(libpeio::libpeio_header_only ALIAS libpeio_header_only)

target_compile_definitions(libpeio_header_only INTERFACE LIBPEIO_HEADER_ONLY=1)
target_compile_features(libpeio_header_only INTERFACE cxx_std_23)

target_include_directories(libpeio_header_only INTERFACE include/)

if(MSVC)
  target_compile_options(
    libpeio_header_only
    INTERFACE
    /utf-8
  )
else(MSVC)
  target_compile_options(
    libpeio_header_only
    INTERFACE
  )
endif(MSVC)

target_link_libraries(libpeio_header_only INTERFACE mio::mio)

# Define examples

if(LIBPEIO_BUILD_ALL OR LIBPEIO_BUILD_EXAMPLE OR LIBPEIO_BUILD_EXAMPLE_HO)

  if(LIBPEIO_BUILD_ALL OR LIBPEIO_BUILD_EXAMPLE)
    add_subdirectory(example/libpeio)
  endif(LIBPEIO_BUILD_ALL OR LIBPEIO_BUILD_EXAMPLE)

  if(LIBPEIO_BUILD_ALL OR LIBPEIO_BUILD_EXAMPLE_HO)
    add_subdirectory(example/libpeio_header_only)
  endif(LIBPEIO_BUILD_ALL OR LIBPEIO_BUILD_EXAMPLE_HO)

endif(LIBPEIO_BUILD_ALL OR LIBPEIO_BUILD_EXAMPLE OR LIBPEIO_BUILD_EXAMPLE_HO)

# Define tests

if(LIBPEIO_BUILD_ALL OR LIBPEIO_BUILD_TESTS OR LIBPEIO_BUILD_TESTS_HO)

  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
  )
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  set(LIBPEIO_TEST_SOURCES test/resolver.cpp)

  if(LIBPEIO_BUILD_ALL OR LIBPEIO_BUILD_TESTS)
    add_executable(${PROJECT_NAME}-googletest ${LIBPEIO_TEST_SOURCES})
    target_link_libraries(${PROJECT_NAME}-googletest libpeio)
    target_link_libraries(${PROJECT_NAME}-googletest gtest_main)
    add_test(NAME test COMMAND ${PROJECT_NAME}-googletest)
  endif(LIBPEIO_BUILD_ALL OR LIBPEIO_BUILD_TESTS)

  if(LIBPEIO_BUILD_ALL OR LIBPEIO_BUILD_TESTS_HO)
    add_executable(${PROJECT_NAME}_header_only-googletest ${LIBPEIO_TEST_SOURCES})
    target_link_libraries(${PROJECT_NAME}_header_only-googletest libpeio_header_only)
    target_link_libraries(${PROJECT_NAME}_header_only-googletest gtest_main)
    add_test(NAME test_header_only COMMAND ${PROJECT_NAME}_header_only-googletest)
  endif(LIBPEIO_BUILD_ALL OR LIBPEIO_BUILD_TESTS_HO)

  enable_testing()

endif(LIBPEIO_BUILD_ALL OR LIBPEIO_BUILD_TESTS OR LIBPEIO_BUILD_TESTS_HO)
