#ifndef AVP64_REST_RECEIVER_H
#define AVP64_REST_RECEIVER_H

#include "testing/test_receiver.h"
#include "vcml/debugging/suspender.h"
#include "vcml/debugging/subscriber.h"
#include "vcml/debugging/target.h"
#include "vcml/core/types.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>
#include <thread>
#include <sys/types.h>
#include <sys/shm.h>

#include "probe.h"
#include "can_injector.h"
#include "test_interface.h"

using namespace vcml::debugging;
using std::string;

namespace testing{

    class avp64_test_receiver final: public test_receiver, public suspender, public subscriber{

        public:

            struct breakpoint{
                const symbol* ptr;
                string name;
                mwr::u64 addr;
            };

            void log_info_message(const char* fmt, ...) override;
        
            void log_error_message(const char* fmt, ...) override;

            avp64_test_receiver(const string& name, probe& get_probe, MMIO_access& mmio_access, Can_injector& can_injector);

            void parse_args(int argc, const char* const* argv);

            ~avp64_test_receiver();

            void run();

            void notify_breakpoint_hit(const vcml::debugging::breakpoint& bp) override;

            void notify_basic_block(target& tgt, mwr::u64 pc, size_t blksz, size_t icount) override;

            void on_mmio_access(vcml::tlm_generic_payload& tx);

            void notify_vp_finished();

            char read_reg_value(string reg_name);

        private:

            status handle_continue() override;

            status handle_kill() override;

            bool find_symbol_address(vcml::u64* addr, string breakpoint_name, bool set_breakpoint);

            std::vector<breakpoint>::iterator find_breakpoint(string name);

            std::vector<breakpoint>::iterator find_breakpoint(mwr::u64 addr);

            void remove_breakpoint(mwr::u64 addr, int vector_idx);

            status handle_set_breakpoint(string &symbol, int offset) override;

            status handle_remove_breakpoint(string &sym_name) override;

            status handle_set_mmio_tracking() override;

            status handle_disable_mmio_tracking() override;

            status handle_set_mmio_value(char* value, size_t length) override;

            status handle_write_mmio_write_queue(char* value, size_t length) override;

            status handle_set_code_coverage() override;

            status handle_reset_code_coverage() override;

            status handle_disable_code_coverage() override;

            string handle_get_code_coverage() override;

            char handle_get_exit_status() override;

            status handle_do_run(std::string start_breakpoint, std::string end_breakpoint, char* mmio_data, size_t mmio_data_length) override;

            probe* m_probe;
            MMIO_access* m_mmio_access;
            Can_injector* m_can_injector;

            bool m_is_sim_suspended = false;

            std::vector<breakpoint> m_active_breakpoints;  

            char m_ret_value = 0;

            bool m_kill_server = false;

            mwr::option<bool> m_enabled_option;
            mwr::option<string> m_communication_option;
            mwr::option<string> m_mq_request_option;
            mwr::option<string> m_mq_response_option;
            mwr::option<string> m_pipe_request_option;
            mwr::option<string> m_pipe_response_option;

            bool m_run_until_breakpoint = false;
            mwr::u64 m_run_until_breakpoint_addr;
            mwr::u64 m_exit_breakpoint_address;
    };

}  //namespace testing

#endif