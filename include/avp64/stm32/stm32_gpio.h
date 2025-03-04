
#ifndef STM32_GPIO
#define STM32_GPIO

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

class stm32_gpio : public peripheral
{

public:

   reg<u32> modder; // GPIO Port Mode Register
   reg<u32> otyper; // GPIO Port Output Type Register
   reg<u32> pupdr; // GPIO Port Pull-up/Pull-down
   reg<u32> idr; // GPIO Port Input Data Register
   reg<u32> bsrr; // GPIO Port Bit Set/Reset Register

   tlm_target_socket in;

   stm32_gpio(const sc_module_name& name);
   virtual ~stm32_gpio();
};

#endif