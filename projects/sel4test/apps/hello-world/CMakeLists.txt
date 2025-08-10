#
# Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.16.0)

project(hello-world C)

find_package(musllibc REQUIRED)
find_package(util_libs REQUIRED)
find_package(seL4_libs REQUIRED)

# Setup build environment
musllibc_setup_build_environment_with_sel4runtime()
sel4_import_libsel4()
util_libs_import_libraries()
sel4_libs_import_libraries()

# Build hello world application
file(GLOB deps src/*.c)
list(SORT deps)

add_executable(hello-world EXCLUDE_FROM_ALL ${deps})
target_link_libraries(hello-world 
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
target_compile_options(hello-world PRIVATE -Werror -g)
set_property(TARGET hello-world PROPERTY C_STANDARD 99)

# Set this image as the rootserver
include(rootserver)
DeclareRootserver(hello-world)
