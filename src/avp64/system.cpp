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
 
 void system::construct_system_avp32() {
     // Clock Bindings
     clk_bind(m_clock_cpu, "clk", m_cpu, "clk");
     clk_bind(m_clock_cpu, "clk", m_bus, "clk");
     clk_bind(m_clock_cpu, "clk", m_flash, "clk");
     clk_bind(m_clock_cpu, "clk", m_ram, "clk");
     clk_bind(m_clock_cpu, "clk", m_stm32_peripherals, "clk");
     clk_bind(m_clock_cpu, "clk", m_stm32_system_control, "clk");
     clk_bind(m_clock_cpu, "clk", m_stm32_gpio, "clk");
     clk_bind(m_clock_cpu, "clk", m_stm32_uart, "clk");
 
     // Reset Bindings
     gpio_bind(m_reset, "rst", m_cpu, "rst");
     gpio_bind(m_reset, "rst", m_bus, "rst");
     gpio_bind(m_reset, "rst", m_flash, "rst");
     gpio_bind(m_reset, "rst", m_ram, "rst");
     gpio_bind(m_reset, "rst", m_stm32_peripherals, "rst");
     gpio_bind(m_reset, "rst", m_stm32_system_control, "rst");
     gpio_bind(m_reset, "rst", m_stm32_gpio, "rst");
     gpio_bind(m_reset, "rst", m_stm32_uart, "rst");
 
     //Fuzzer:
     tlm_bind(m_cpu,"bus",m_mmio_probe, "probe_in");
     tlm_bind(m_bus, m_mmio_probe, "probe_out");

     // TLM Bindings
     //tlm_bind(m_bus, m_cpu, "bus");
     tlm_bind(m_bus, m_flash, "in", addr_flash);
     tlm_bind(m_bus, m_ram, "in", addr_ram);
     tlm_bind(m_bus, m_stm32_peripherals, "in", { 0x40020000, 0x4002ffff });
     tlm_bind(m_bus, m_stm32_system_control, "in", { 0xE0000000, 0xEfffffff });
     tlm_bind(m_bus, m_stm32_gpio, "in", { 0x48000000, 0x48ffffff });
     tlm_bind(m_bus, m_stm32_uart, "in", { 0x40013800, 0x400138ff });
 }
 
 system::system(const sc_core::sc_module_name& nm):
     vcml::system(nm),
     addr_flash("addr_flash"),
     addr_ram("addr_ram"),
     m_clock_cpu("clock_cpu", 1 * mwr::GHz),
     m_reset("reset"),
     m_bus("bus"),
     m_flash("flash", addr_flash.get().length()),
     m_ram("ram", addr_ram.get().length()),
     m_stm32_peripherals("stm32_peripherals"),
     m_stm32_system_control("stm32_system_control"),
     m_stm32_gpio("stm32_gpio"),
     m_stm32_uart("stm32_uart"),
     m_cpu("cpu"),
     m_mmio_probe("probe"),
     m_testing_receiver("testing_receiver", this->m_mmio_probe, m_cpu.get_core(0)){
        construct_system_avp32();

        // Setting notify_mmio_access callback.
        m_mmio_probe.notify_mmio_access = std::bind(&testing::avp64_testing_receiver::on_mmio_access, &m_testing_receiver, std::placeholders::_1, std::placeholders::_2);
 }

 void system::parse_args(int argc, const char* const* argv){
      m_testing_receiver.parse_args(argc, argv);
 }
 
 int system::run() {

     // TODO earlier ?
     m_testing_receiver.init();

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
 
     m_testing_receiver.notify_vp_finished();

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
 