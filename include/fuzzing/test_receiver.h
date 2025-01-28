#ifndef TestReceiver_h
#define TestReceiver_h

#include <semaphore.h>
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

#define LOG_INFO(fmt, ...) vcml::log_info("TEST_INTERFACE: " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) vcml::log_error("TEST_INTERFACE: " fmt, ##__VA_ARGS__)

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)

namespace fuzzing{

    class test_receiver final: public suspender, public subscriber{

        public:

            enum status {
                STATUS_OK, MMIO_READ, MMIO_WRITE, VP_END, BREAKPOINT_HIT, ERROR=-1
            };

            struct breakpoint{
                const symbol* ptr;
                string name;
                mwr::u64 addr;
            };

            test_receiver(const string& name, MMIO_access& mmio_access, Can_injector& can_injector);

            void parse_args(int argc, const char* const* argv);

            ~test_receiver();

            void run();

            void notify_breakpoint_hit(const vcml::debugging::breakpoint& bp) override;

            void notify_basic_block(target& tgt, mwr::u64 pc, size_t blksz, size_t icount) override;

            void on_mmio_access(vcml::tlm_generic_payload& tx);

            void notify_vp_finished();

            char read_reg_value(string reg_name);

        private:
    
            void receiver();

            void handle_request(test_interface::request* req, test_interface::response* res);

            status handle_continue();

            status handle_kill();

            std::vector<breakpoint>::iterator find_breakpoint(string name);
            std::vector<breakpoint>::iterator find_breakpoint(mwr::u64 addr);

            status handle_set_breakpoint(string &symbol, int offset);

            status handle_remove_breakpoint(string &sym_name);

            void remove_breakpoint(mwr::u64 addr, int vector_idx);

            status handle_set_mmio_tracking();

            status handle_disable_mmio_tracking();

            status handle_set_mmio_value(char* value, size_t length);

            status handle_set_code_coverage();

            status handle_reset_code_coverage();

            status handle_disable_code_coverage();

            string handle_get_code_coverage();

            char handle_get_exit_status();

            status handle_do_run(std::string start_breakpoint, std::string end_breakpoint, int shm_id, unsigned int offset);

            status handle_write_code_coverage(int shm_id, unsigned int offset);

            std::thread m_interface_thread;

            MMIO_access* m_mmio_access;
            Can_injector* m_can_injector;

            sem_t m_full_slots, m_empty_slots;
            std::deque<status> m_exit_id_buffer;

            bool m_is_sim_suspended = false;

            std::vector<breakpoint> m_active_breakpoints;  

            char m_ret_value = 0;

            bool m_kill_server = false;

            mwr::u8 m_bb_array [MAP_SIZE];
            mwr::u64 m_prev_bb_loc = 0;

            mwr::option<string> m_communication_option;

            test_interface* m_interface;

    };

};

#endif