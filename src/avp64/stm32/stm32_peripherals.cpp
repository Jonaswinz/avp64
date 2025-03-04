#include "avp64/stm32/stm32_peripherals.h"

stm32_peripherals::stm32_peripherals(const sc_module_name& nm):
    peripheral(nm),
    flash_acr("flash_acr", 0x2000, 0x00000001), // 0x40022000 Default: Latency = 1
    rcc_apb1enr("rcc_apb1enr", 0x101c, 0x00000000), // 0x4002101C
    rcc_apb2enr("rcc_apb2enr", 0x1018, 0x00000000), // 0x40021018
    rcc_cfgr1("rcc_cfgr1", 0x1004, 0x0028000A), // 0x40021004 Default: SWS = 10 → PLL as SYSCLK, HPRE = /1, PPRE = /1
    rcc_cfgr2("rcc_cfgr2", 0x1010, 0x00000000), // 0x40021010 Default: None
    rcc_cfgr3("rcc_cfgr3", 0x1030, 0x00000000), // 0x40021030 Default: None
    rcc_cfgr4("rcc_cfgr4", 0x1034, 0x00000000), // 0x40021034 Default: None
    rcc_cr("rcc_cr", 0x1000, 0x03000003), // 0x40021000 Default: HSI on and ready & PLL on and ready, required for 48Mhz
    rcc_bdcr("rcc_bdcr", 0x102C, 0x00000000), // 0x4002102c Default: No LSE, No RTC
    rcc_ahbenr("rcc_ahbenr", 0x1014, 0x00004002), // 0x40021014 Default: GPIOAEN = 1, DMAEN = 1
    rcc_crrcr("rcc_crrcr", 0x1008, 0x40000000), // 0x40021008 Default: HSI48 is enabled and ready (HSI48RDY = 1)
    adc1_cr1("adc1_cr1", 0x3008, 0x00000000), // 0x40023008 Default: None
    adc1_cr2("adc1_cr2", 0x3010, 0x00000000), // 0x40023010 Default: None
    in("in"){

        rcc_cfgr1.on_write(&stm32_peripherals::write_rcc_cfgr1);
    } 


stm32_peripherals::~stm32_peripherals() {
    // nothing to do
}

void stm32_peripherals::write_rcc_cfgr1(u32 val) {
    // Do not update the register value. During the bootup this register will be written and then requested afterwards. The default "enabled" value should be kept.
}