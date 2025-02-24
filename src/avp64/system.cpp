/******************************************************************************
 *                                                                            *
 * Copyright 2024 Lukas Jünger, Nils Bosbach                                  *
 *                                                                            *
 * This software is licensed under the MIT license found in the               *
 * LICENSE file at the root directory of this source tree.                    *
 *                                                                            *
 ******************************************************************************/

 #include "avp64/system.h"
 #include "avp64/version.h"
 
 namespace avp64 {
 
 void system::construct_system_rp2350() {
     // Clock Bindings
     clk_bind(m_clock_cpu, "clk", m_cpu, "clk");
     clk_bind(m_clock_cpu, "clk", m_bus, "clk");
     clk_bind(m_clock_cpu, "clk", m_rom, "clk");
     clk_bind(m_clock_cpu, "clk", m_flash, "clk");
     clk_bind(m_clock_cpu, "clk", m_ram, "clk");
     clk_bind(m_clock_cpu, "clk", m_uart0, "clk");
     clk_bind(m_clock_cpu, "clk", m_gpio, "clk");
 
     // Reset Bindings
     gpio_bind(m_reset, "rst", m_cpu, "rst");
     gpio_bind(m_reset, "rst", m_bus, "rst");
     gpio_bind(m_reset, "rst", m_rom, "rst");
     gpio_bind(m_reset, "rst", m_flash, "rst");
     gpio_bind(m_reset, "rst", m_ram, "rst");
     gpio_bind(m_reset, "rst", m_uart0, "rst");
     gpio_bind(m_reset, "rst", m_gpio, "rst");
 
     // TLM Bindings
     tlm_bind(m_bus, m_cpu, "bus");
     tlm_bind(m_bus, m_rom, "in", addr_rom);
     tlm_bind(m_bus, m_flash, "in", addr_flash);
     tlm_bind(m_bus, m_ram, "in", addr_ram);
     tlm_bind(m_bus, m_uart0, "in", addr_uart0);
     tlm_bind(m_bus, m_gpio, "in", addr_gpio);
 
     // Connect UART to terminal
     serial_bind(m_term0, "serial_tx", m_uart0, "serial_rx");
     serial_bind(m_term0, "serial_rx", m_uart0, "serial_tx");
 
     // IRQs
     gpio_bind(m_uart0, "irq", m_cpu, "spi", irq_uart0);
     //gpio_bind(m_gpio, "irq", m_cpu, "spi", irq_gpio);
 }
 
 system::system(const sc_core::sc_module_name& nm):
     vcml::system(nm),
     addr_rom("addr_rom"),
     addr_flash("addr_flash"),
     addr_ram("addr_ram"),
     addr_uart0("addr_uart0"),
     addr_gpio("addr_gpio"),
     irq_uart0("irq_uart0"),
     irq_gpio("irq_gpio"),
     m_clock_cpu("clock_cpu", 1 * mwr::GHz),
     m_reset("reset"),
     m_bus("bus"),
     m_rom("rom", addr_rom.get().length()),
     m_flash("flash", addr_flash.get().length()),
     m_ram("ram", addr_ram.get().length()),
     m_uart0("uart0"),
     m_gpio("gpio"),
     m_term0("term0"),
     m_cpu("cpu") {
     construct_system_rp2350();
 }
 
 int system::run() {
     double simstart = mwr::timestamp();
     int result = vcml::system::run();
     double realtime = mwr::timestamp() - simstart;
     double duration = sc_core::sc_time_stamp().to_seconds();
     vcml::u64 ninsn = m_cpu.cycle_count();
 
     double mips = realtime == 0.0 ? 0.0 : ninsn / realtime / 1e6;
     vcml::log_info("total");
     vcml::log_info("  duration       : %.9fs", duration);
     vcml::log_info("  runtime        : %.4fs", realtime);
     vcml::log_info("  instructions   : %llu", ninsn);
     vcml::log_info("  sim speed      : %.1f MIPS", mips);
     vcml::log_info("  realtime ratio : %.2f / 1s",
                    realtime == 0.0 ? 0.0 : realtime / duration);
 
     return result;
 }
 
 void system::end_of_elaboration() {
     vcml::system::end_of_elaboration();
 
     std::stringstream ss;
     m_bus.execute("show", ss);
     log_debug("%s", ss.str().c_str());
 }
 
 const char* system::version() const {
     return AVP64_VERSION_STRING;
 }
 
 } // namespace avp64
 