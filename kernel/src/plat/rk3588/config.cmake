##
# rk3588 platform configuration (based on rk3568)
##

declare_platform(rk3588 KernelPlatformRk3588 PLAT_RK3588 KernelSel4ArchAarch64)

if(KernelPlatformRk3588)
    declare_seL4_arch(aarch64)
    set(KernelArmCortexA55 ON)
    set(KernelArchArmV8a ON)
    set(KernelArmGicV3 ON)
    config_set(KernelARMPlatform ARM_PLAT rk3588)
    list(APPEND KernelDTSList "tools/dts/rk3588.dts")
    list(APPEND KernelDTSList "src/plat/rk3588/overlay-rk3588.dts")

    declare_default_headers(
        TIMER_FREQUENCY 24000000
        MAX_IRQ 520
        NUM_PPI 32
        TIMER drivers/timer/arm_generic.h
        INTERRUPT_CONTROLLER arch/machine/gic_v3.h
        KERNEL_WCET 10u
    )
endif()

add_sources(
    DEP "KernelPlatformRk3588" CFILES src/arch/arm/machine/gic_v3.c src/arch/arm/machine/l2c_nop.c
)
