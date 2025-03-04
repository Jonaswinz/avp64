
#ifndef STM32_SYSTEM_CONTROL
#define STM32_SYSTEM_CONTROL

#include "vcml/core/types.h"
#include "vcml/core/systemc.h"
#include "vcml/core/range.h"
#include "vcml/core/peripheral.h"
#include "vcml/core/model.h"

using vcml::reg;
using vcml::peripheral;
using vcml::u32;
using vcml::sc_module_name;
using vcml::tlm_target_socket;

class stm32_system_control : public peripheral
{
public:

    reg<u32> scb_aircr; // Application Interrupt and Reset Control Register
    reg<u32> syst_rvr; // SysTick Reload Value Register
    reg<u32> syst_cvr; // SysTick Current Value Register
    reg<u32> syst_csr; // SysTick Control and Status Register

    tlm_target_socket in;

    stm32_system_control(const sc_module_name& name);
    virtual ~stm32_system_control();
};

#endif