cmake_minimum_required(VERSION 3.20)
project(libpeio_header_only-example VERSION 1.0.0 LANGUAGES CXX)

add_executable(${PROJECT_NAME} main.cpp)

# For stand-alone build
# (For example, if you use a git submodule)
if(NOT TARGET libpeio)
  find_package(libpeio REQUIRED)
endif()

## Recommended build style
# include(FetchContent)
# FetchContent_Declare(
#   libpeio
#   GIT_REPOSITORY https://github.com/Yamanekazuma/libpeio.git
#   GIT_TAG v1.0.0  # Choose any version
# )
# FetchContent_MakeAvailable(libpeio)

target_link_libraries(${PROJECT_NAME} libpeio::libpeio_header_only)
