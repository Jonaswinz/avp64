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
 
 #include "vcml.h"
 #include "avp64.h"
 
 namespace avp64 {

 class system : public vcml::system
 {
 public:
     // properties
     vcml::property<vcml::range> addr_rom;
     vcml::property<vcml::range> addr_flash;
     vcml::property<vcml::range> addr_ram;
     vcml::property<vcml::range> addr_uart0;
     vcml::property<vcml::range> addr_gpio;
 
     vcml::property<int> irq_uart0;
     vcml::property<int> irq_gpio;
 
     system(const sc_core::sc_module_name& name);
     system() = delete;
     system(const system&) = delete;
     virtual ~system() = default;
 
     int run() override;
 
     virtual void end_of_elaboration() override;
 
     const char* version() const override;
     virtual const char* kind() const override { return "avp64::system"; }
 
 private:
     vcml::generic::clock m_clock_cpu;
     vcml::generic::reset m_reset;
     vcml::generic::bus m_bus;
     vcml::generic::memory m_rom;
     vcml::generic::memory m_flash;
     vcml::generic::memory m_ram;
     vcml::serial::pl011 m_uart0;
     vcml::gpio::mmgpio m_gpio;
     vcml::serial::terminal m_term0;
 
     cpu m_cpu;
 
     void construct_system_rp2350();
 };
 
 } // namespace avp64
 
 #endif // AVP64_SYSTEM_H
 