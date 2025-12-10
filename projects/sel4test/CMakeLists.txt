#
# Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.16.0)

include(settings.cmake)

project(sel4test C CXX ASM)

find_package(seL4 REQUIRED)
find_package(elfloader-tool REQUIRED)

# Set the roottask CNode size to be large enough for DTB, timer caps, etc
# Note that this works for the platforms that we have at the moment, and may
# need to be increased in the future
set(KernelRootCNodeSizeBits 13 CACHE INTERNAL "")

# Set our custom domain schedule
set(KernelDomainSchedule "${CMAKE_CURRENT_LIST_DIR}/domain_schedule.c" CACHE INTERNAL "")
sel4_import_kernel()

if((NOT Sel4testAllowSettingsOverride) AND (KernelArchARM OR KernelArchRiscV))
    # Elfloader settings that correspond to how Data61 sets its boards up.
    ApplyData61ElfLoaderSettings(${KernelPlatform} ${KernelSel4Arch})
endif()
elfloader_import_project()

# Allow choosing between different applications
set(Sel4testApp "sel4test-driver" CACHE STRING "Application to build (sel4test-driver, hello-world, or hyperamp-server)")
set_property(CACHE Sel4testApp PROPERTY STRINGS sel4test-driver hello-world hyperamp-server)

if(Sel4testApp STREQUAL "hello-world")
    add_subdirectory(apps/hello-world)
elseif(Sel4testApp STREQUAL "hyperamp-server")
    add_subdirectory(apps/hyperamp-server)
else()
    add_subdirectory(apps/sel4test-driver)
endif()

if(SIMULATION)
    include(simulation)
    if(KernelSel4ArchX86_64)
        SetSimulationScriptProperty(MEM_SIZE "3G")
    endif()
    if(KernelPlatformQEMUArmVirt)
        SetSimulationScriptProperty(MEM_SIZE "2G")
    endif()
    GenerateSimulateScript()
endif()
