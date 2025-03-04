#include "avp64/stm32/stm32_uart.h"

stm32_uart::stm32_uart(const sc_module_name& nm):
    peripheral(nm),
    cr1("cr1", 0x0, 0x00000000),
    cr2("cr2", 0x4, 0x00000000),
    cr3("cr3", 0x8, 0x00000000),
    cr4("cr4", 0xc, 0x00000000),
    isr("isr", 0x1c, 0x000000a0), // Set RXNE to indicate read data and set TXE flag according to stm32f0xx_hal_usart.c 916
    tdr("tdr", 0x28, 0x00000000),
    rdr("rdr", 0x24, 0x00000005), // Read data 1 Byte = 3
    in("in"){

        cr1.on_write(&stm32_uart::write_cr1);
        cr2.on_write(&stm32_uart::write_cr2);
        cr3.on_write(&stm32_uart::write_cr3);
        cr4.on_write(&stm32_uart::write_cr4);
    } 

stm32_uart::~stm32_uart() {
    // nothing to do
}

void stm32_uart::write_cr1(u32 val) {
    // Do not update the register value.
}

void stm32_uart::write_cr2(u32 val) {
    // Do not update the register value.
}

void stm32_uart::write_cr3(u32 val) {
    // Do not update the register value.
}

void stm32_uart::write_cr4(u32 val) {
    // Do not update the register value.
}