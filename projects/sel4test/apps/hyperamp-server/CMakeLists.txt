#
# HyperAMP Server for seL4 - Compatible with HighSpeedCProxy
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.16.0)

project(hyperamp-server C)

find_package(musllibc REQUIRED)
find_package(util_libs REQUIRED)
find_package(seL4_libs REQUIRED)

# Setup build environment
musllibc_setup_build_environment_with_sel4runtime()
sel4_import_libsel4()
util_libs_import_libraries()
sel4_libs_import_libraries()

# Build HyperAMP server application
file(GLOB deps src/*.c)
list(SORT deps)

add_executable(hyperamp-server EXCLUDE_FROM_ALL ${deps})

# Add include directories for HyperAMP headers (本地 include 目录)
target_include_directories(hyperamp-server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(hyperamp-server 
    PUBLIC
        sel4_autoconf
        muslc
        sel4
        sel4runtime
        sel4utils
        sel4platsupport
        sel4muslcsys
        sel4allocman
    PRIVATE
        utils
)

# Set executable properties 
target_compile_options(hyperamp-server PRIVATE -Werror -g -O2)
set_property(TARGET hyperamp-server PROPERTY C_STANDARD 99)

# Set this image as the rootserver
include(rootserver)
DeclareRootserver(hyperamp-server)
