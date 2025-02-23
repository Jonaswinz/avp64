#ifndef AVP64_TESTING_RECEIVER_H
#define AVP64_TESTING_RECEIVER_H

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

#include "mmio_probe.h"

#include "testing_receiver.h"
#include "testing_communication.h"

using namespace vcml::debugging;
using std::string;
using testing::testing_communication;

namespace testing{

    class avp64_testing_receiver final: public testing_receiver, public suspender, public subscriber{

        public:

            struct breakpoint{
                const symbol* ptr;
                string name;
                mwr::u64 addr;
            };

            struct mmio_event{
                sem_t* mutex;
                vcml::tlm_generic_payload* payload;
            };

            void log_info_message(const char* fmt, ...) override;
        
            void log_error_message(const char* fmt, ...) override;

            avp64_testing_receiver(const string& name, mmio_probe& get_probe);

            void parse_args(int argc, const char* const* argv);

            ~avp64_testing_receiver();

            void init();

            void notify_breakpoint_hit(const vcml::debugging::breakpoint& bp) override;

            void notify_basic_block(target& tgt, mwr::u64 pc, size_t blksz, size_t icount) override;

            void on_mmio_access(vcml::tlm_generic_payload& tx);

            void notify_vp_finished();

            bool read_reg_value(uint64_t &read_val, string reg_name);

        private:

            status handle_continue(event &last_event) override;

            status handle_kill(bool gracefully) override;

            bool find_symbol_address(vcml::u64* addr, string breakpoint_name, bool set_breakpoint);

            std::vector<breakpoint>::iterator find_breakpoint(string name);

            std::vector<breakpoint>::iterator find_breakpoint(mwr::u64 addr);

            status handle_set_breakpoint(string &symbol, int offset) override;

            void remove_breakpoint(mwr::u64 addr, int vector_idx);

            status handle_remove_breakpoint(string &sym_name) override;

            status handle_enable_mmio_tracking(uint64_t start_address, uint64_t end_address, char mode) override;

            status handle_disable_mmio_tracking() override;

            status handle_set_mmio_value(size_t length, char* value) override;

            status handle_add_to_mmio_read_queue(uint64_t address, size_t length, size_t element_count, char* value) override;

            status handle_trigger_cpu_interrupt(uint8_t interrupt) override;

            status handle_enable_code_coverage() override;

            status handle_reset_code_coverage() override;

            status handle_disable_code_coverage() override;

            status handle_get_code_coverage(string* coverage) override;

            status handle_set_return_code_address(uint64_t address, std::string reg_name) override;

            status handle_get_return_code(uint64_t &code) override;

            status handle_do_run(std::string start_breakpoint, std::string end_breakpoint, uint64_t mmio_address, size_t mmio_length, size_t mmio_element_count, char* mmio_value) override;

            // Stopping the whole VP, when error occured or killing non gracefully.
            void shutdown();

            void suspend_simulation();

            void resume_simulation();

            mmio_probe* m_mmio_probe;

            bool m_is_sim_suspended = false;

            std::vector<breakpoint> m_active_breakpoints;  
            std::mutex m_active_breakpoints_mutex;

            std::vector<mmio_event> m_mmio_event_queue;  
            std::mutex m_mmio_event_queue_mutex;

            std::string m_ret_register;
            uint64_t m_ret_address = 0;
            bool m_ret_recording_enabled = false;
            uint64_t m_ret_value = 0;
            bool m_ret_value_set = false;

            bool m_kill_server = false;

            mwr::option<bool> m_enabled_option;
            mwr::option<string> m_communication_option;
            mwr::option<string> m_mq_request_option;
            mwr::option<string> m_mq_response_option;
            mwr::option<string> m_pipe_request_option;
            mwr::option<string> m_pipe_response_option;

            bool m_run_until_breakpoint = false;
            mwr::u64 m_run_until_breakpoint_addr;
    };

}  //namespace testing

#endif