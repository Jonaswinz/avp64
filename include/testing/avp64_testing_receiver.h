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

    // Implementation of the testing_receiver class for AVP64 virtual platform.
    class avp64_testing_receiver final: public testing_receiver, public suspender, public subscriber{

        public:

            // Represents a tracked breakpoint.
            struct breakpoint{
                const symbol* ptr;
                string name;
                mwr::u64 addr;
            };

            // Represents a mmio event.
            struct mmio_event{
                sem_t* mutex;
                vcml::tlm_generic_payload* payload;
                size_t offset = 0;
            };

            // Constructs the testing_receiver for AVP64 with a SystemC name and a reference to the mmio_probe.
            avp64_testing_receiver(const string& name, mmio_probe& get_probe);

            // Destructor.
            ~avp64_testing_receiver();

            // Parses required vcml options to get the settings for this testing_receiver.
            void parse_args(int argc, const char* const* argv);

            // Initializes everything (mainly the testing_communication) according to the vcml options.
            void init();

            // Implementes the log_info_message method by using vcml logging. 
            void log_info_message(const char* fmt, ...) override;
            
            // Implementes the log_error_message method by using vcml logging. 
            void log_error_message(const char* fmt, ...) override;

            // Function of subscriber class to get notifications of breakpoint hits of the cores.
            void notify_breakpoint_hit(const vcml::debugging::breakpoint& bp) override;
            
            // Function of subscriber class to get notifications of basic block executions. This is used for code coverage recording.
            void notify_basic_block(target& tgt, mwr::u64 pc, size_t blksz, size_t icount) override;

            // Callback for the mmio_probe to call when a MMIO access should be handeled.
            void on_mmio_access(vcml::tlm_generic_payload& tx, size_t offset);

            // Callback, when the target programs finished its execution.
            void notify_vp_finished();

        private:

            // Implementation of the CONTINUE command.
            status handle_continue(event &last_event) override;

            // Implementation of the KILL command.
            status handle_kill(bool gracefully) override;

            // Find the address of a symbol by its name. This function can also set a breakpoint to it, without the management via the m_active_breakpoint vector. This is for example used by the run_until mode.
            bool find_symbol_address(vcml::u64* addr, string &breakpoint_name, bool set_breakpoint);

            // Find a breakpoint inside the m_active_breakpoints vector by its name.
            std::vector<breakpoint>::iterator find_breakpoint(string name);

            // Find a breakpoint inside the m_active_breakpoints vector by its address.
            std::vector<breakpoint>::iterator find_breakpoint(mwr::u64 addr);
            
            // Removed a breakpoint from the m_active_breakpoints vector by its address and index.
            void remove_breakpoint(mwr::u64 addr, int vector_idx);

            // Implementation of the SET_BREAKPOINT command. This will add the breakpoint to the m_active_breakpoint vector.
            status handle_set_breakpoint(string &symbol, int offset) override;

            // Implementation of the REMOVE_BREAKPOINT command.
            status handle_remove_breakpoint(string &sym_name) override;

            // Implementation of the ENABLE_MMIO_TRACKING command.
            status handle_enable_mmio_tracking(uint64_t start_address, uint64_t end_address, char mode) override;

            // Implementation of the DISABLE_MMIO_TRACKING command.
            status handle_disable_mmio_tracking() override;

            // Implementation of the SET_MMIO_VALUE command.
            status handle_set_mmio_value(size_t length, char* value) override;

            // Implementation of the ADD_TO_READ_QUEUE command.
            status handle_add_to_mmio_read_queue(uint64_t address, size_t length, char* value) override;

            // Implementation of the TRIGGER_CPU_INTERRUPT command.
            status handle_trigger_cpu_interrupt(uint8_t interrupt) override;

            // Implementation of the ENABLE_CODE_COVERAGE command.
            status handle_enable_code_coverage() override;

            // Implementation of the RESET_CODE_COVERAGE command.
            status handle_reset_code_coverage() override;

            // Implementation of the DISABLE_CODE_COVERAEG command.
            status handle_disable_code_coverage() override;

            // Implementation of the GET_CODE_COVERAGE command.
            status handle_get_code_coverage(string* coverage) override;

            // Implementation of the SET_RETURN_CODE_ADDRESS command.
            status handle_set_return_code_address(uint64_t address, std::string &reg_name) override;

            // Implementation of the GET_RETURN_CODE command.
            status handle_get_return_code(uint64_t &code) override;

            // Implementation of the DO_RUN command.
            status handle_do_run(std::string &start_breakpoint, std::string &end_breakpoint, uint64_t mmio_address, size_t mmio_length, char* mmio_value, std::string &register_name) override;

            // Stopping the whole VP, when error occured or killing non gracefully.
            void shutdown();

            // Helper function to suspend the simulation.
            void suspend_simulation();

            // Helper function to resume the simulation.
            void resume_simulation();

            // Helper function to read a register of the CPU, by its name.
            bool read_reg_value(uint64_t &read_val, string &reg_name);

            // Reference to the mmio_probe used.
            mmio_probe* m_mmio_probe;

            // Indicator if the simulation is suspended / was suspened by this class.
            bool m_is_sim_suspended = false;

            // Management for the active breakpoints.
            std::vector<breakpoint> m_active_breakpoints;  
            std::mutex m_active_breakpoints_mutex;

            // Management for the mmio event queue.
            std::vector<mmio_event> m_mmio_event_queue;  
            std::mutex m_mmio_event_queue_mutex;

            // Setting of the return code recording is enabled.
            bool m_ret_recording_enabled = false;

            // Address of the instruction where the return code should be recorded.
            uint64_t m_ret_address = 0;

            // Name of the return register that should be recorded.
            std::string m_ret_register;
            
            // Value of the return code (if recorded).
            uint64_t m_ret_value = 0;

            // Indicator if the return code was successfully recorded.
            bool m_ret_value_set = false;

            // Indicator if the whole VP should be killed.
            bool m_kill_server = false;

            // Setting if the run_until mode is enabled.
            bool m_run_until_breakpoint = false;

            // Address of the release of the run_until mode.
            mwr::u64 m_run_until_breakpoint_addr;

            // Options to set the settings of this testing_receiver.
            mwr::option<bool> m_enabled_option;
            mwr::option<string> m_communication_option;
            mwr::option<string> m_mq_request_option;
            mwr::option<string> m_mq_response_option;
            mwr::option<string> m_pipe_request_option;
            mwr::option<string> m_pipe_response_option;
    };

}  //namespace testing

#endif