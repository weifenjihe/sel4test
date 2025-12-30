cmake_minimum_required(VERSION 3.16.0)

project(helloworld C)

find_package(musllibc REQUIRED)
find_package(util_libs REQUIRED)
find_package(seL4_libs REQUIRED)
find_package(sel4_projects_libs REQUIRED)

# Setup build environment and import libraries
set(UserLinkerGCSections OFF CACHE BOOL "" FORCE)
musllibc_setup_build_environment_with_sel4runtime()
sel4_import_libsel4()
util_libs_import_libraries()
sel4_libs_import_libraries()
sel4_projects_libs_import_libraries()

add_config_library(helloworld "")

file(
    GLOB
        static
        src/*.c
        src/arch/${KernelArch}/*.c
        src/plat/${KernelPlatform}/*.c
)

add_executable(helloworld EXCLUDE_FROM_ALL ${static})
target_include_directories(helloworld PRIVATE "include")
target_link_libraries(
    helloworld
    PUBLIC
        sel4_autoconf
        muslc
        sel4
        sel4runtime
        sel4platsupport
        sel4muslcsys
    PRIVATE helloworld_Config
)

target_compile_options(helloworld PRIVATE -Werror -g)

# Set this image as the rootserver
include(rootserver)
DeclareRootserver(helloworld)
