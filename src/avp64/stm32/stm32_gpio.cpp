#include "avp64/stm32/stm32_gpio.h"

stm32_gpio::stm32_gpio(const sc_module_name& nm):
    peripheral(nm),
    modder("modder", 0x0, 0x00000000),
    otyper("otyper", 0x4, 0x00000000),
    pupdr("pupdr", 0x8, 0x00000000),
    idr("idr", 0xc, 0x00000000),
    bsrr("bsrr", 0x20, 0x00000000),
    in("in"){} 


stm32_gpio::~stm32_gpio() {
    // nothing to do
}