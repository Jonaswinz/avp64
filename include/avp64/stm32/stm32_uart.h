
#ifndef STM32_UART
#define STM32_UART

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

class stm32_uart : public peripheral
{
private:
    void write_cr1(u32 val);
    void write_cr2(u32 val);
    void write_cr3(u32 val);
    void write_cr4(u32 val);

public:

   reg<u32> cr1; // Setting Register
   reg<u32> cr2; // Setting Register
   reg<u32> cr3; // Setting Register
   reg<u32> cr4; // Setting Register
   reg<u32> isr; // Control Register
   reg<u32> tdr; // Transfer Register
   reg<u32> rdr; // Receive Register

   tlm_target_socket in;

   stm32_uart(const sc_module_name& name);
   virtual ~stm32_uart();
};

#endif