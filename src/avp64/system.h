/******************************************************************************
 *                                                                            *
 * Copyright 2024 Lukas Jünger, Nils Bosbach                                  *
 *                                                                            *
 * This software is licensed under the MIT license found in the               *
 * LICENSE file at the root directory of this source tree.                    *
 *                                                                            *
 ******************************************************************************/

 #ifndef AVP64_SYSTEM_H
 #define AVP64_SYSTEM_H
 
 #include "avp64/stm32/stm32_gpio.h"
 #include "avp64/stm32/stm32_uart.h"
 #include "avp64/stm32/stm32_peripherals.h"
 #include "avp64/stm32/stm32_system_control.h"
 #include "vcml.h"
 #include "avp64.h"
 #include "testing/avp64_testing_receiver.h"
 
 namespace avp64 {

 class system : public vcml::system
 {
 public:
     // properties
     vcml::property<vcml::range> addr_flash;
     vcml::property<vcml::range> addr_ram;
 
     system(const sc_core::sc_module_name& name);
     system() = delete;
     system(const system&) = delete;
     virtual ~system() = default;
    
     void parse_args(int argc, const char* const* argv);

     int run() override;
 
     virtual void end_of_elaboration() override;
 
     const char* version() const override;
     virtual const char* kind() const override { return "avp64::system"; }
 
 private:
     vcml::generic::clock m_clock_cpu;
     vcml::generic::reset m_reset;
     vcml::generic::bus m_bus;
     vcml::generic::memory m_flash;
     vcml::generic::memory m_ram;
     stm32_peripherals m_stm32_peripherals;
     stm32_system_control m_stm32_system_control;
     stm32_gpio m_stm32_gpio;
     stm32_uart m_stm32_uart;
 
     cpu m_cpu;

     testing::mmio_probe m_mmio_probe;
     testing::avp64_testing_receiver m_testing_receiver;
 
     void construct_system_avp32();
 };
 
 } // namespace avp64
 
 #endif // AVP64_SYSTEM_H
 