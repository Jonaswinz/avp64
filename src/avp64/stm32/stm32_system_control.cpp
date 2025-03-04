#include "avp64/stm32/stm32_system_control.h"
 
stm32_system_control::stm32_system_control(const sc_module_name& nm):
    peripheral(nm),
    scb_aircr("scb_aircr", 0xed20, 0x00000000), // 0xE000ED20
    syst_rvr("syst_rvr", 0xe014, 0x00000000), // 0xE000E014
    syst_cvr("syst_cvr", 0xe018, 0x00000000), // 0xE000E018
    syst_csr("syst_csr", 0xe010, 0x00000000), // 0xE000E010
    in("in"){} 

stm32_system_control::~stm32_system_control() {
    // nothing to do
}