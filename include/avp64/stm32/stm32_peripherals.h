
 #ifndef STM32_PERIPHERALS
 #define STM32_PERIPHERALS
 
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

 class stm32_peripherals : public peripheral
 {
private:
    void write_rcc_cfgr1(u32 val);

 public:
 
    reg<u32> flash_acr; // Flash Control Register
    reg<u32> rcc_apb1enr; // APB1 Peripheral Clock Enable Register
    reg<u32> rcc_apb2enr; // APB2 Peripheral Clock Enable Register
    reg<u32> rcc_cfgr1; // Clock Configuration Register 1
    reg<u32> rcc_cfgr2; // Clock Configuration Register 2
    reg<u32> rcc_cfgr3; // Clock Configuration Register 3
    reg<u32> rcc_cfgr4; // Clock Configuration Register 4
    reg<u32> rcc_cr; // Clock Control Register
    reg<u32> rcc_bdcr; // Clock Backup Domain Control Register
    reg<u32> rcc_ahbenr; // AHB Peripheral Clock Enable Register
    reg<u32> rcc_crrcr; // Clock Recovery RC Register
    reg<u32> adc1_cr1; // ADC1 Controll Register
    reg<u32> adc1_cr2; // ADC2 Controll Register

    tlm_target_socket in;

    stm32_peripherals(const sc_module_name& name);
    virtual ~stm32_peripherals();
 };
 
 #endif