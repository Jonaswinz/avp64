#ifndef TEST_RECEIVER_H
#define TEST_RECEIVER_H

#include <semaphore.h>
#include <sys/shm.h>

#include "testing/test_interface.h"
using namespace vcml::debugging;
using std::string;

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)

namespace testing{

    class test_receiver{

        public:   

            enum status {
                STATUS_OK, MMIO_READ, MMIO_WRITE, VP_END, BREAKPOINT_HIT, ERROR=-1
            };

            test_receiver();

            ~test_receiver();

            bool start(test_interface* interface);

            bool start_receiver_in_thread();

            status handle_do_run_shm(std::string start_breakpoint, std::string end_breakpoint, int shm_id, unsigned int offset);

            status handle_get_code_coverage_shm(int shm_id, unsigned int offset);

        protected:

            void receiver();

            virtual void log_info_message(const char* fmt, ...);

            virtual void log_error_message(const char* fmt, ...);

            void continue_to_next_event();
        
            void wait_for_events_processes();
        
            void notify_event();
        
            void wait_for_event();
        
            bool is_event_queue_empty();
        
            void add_event_to_queue(test_receiver::status event);
        
            status get_and_remove_first_event();

            void reset_code_coverage();

            string get_code_coverage();

            void set_block(mwr::u64 pc);

        private:

            void handle_request(test_interface::request* req, test_interface::response* res);

            virtual status handle_continue() = 0;

            virtual status handle_kill() = 0;

            virtual status handle_set_breakpoint(string &symbol, int offset) = 0;

            virtual status handle_remove_breakpoint(string &sym_name) = 0;

            virtual status handle_set_mmio_tracking() = 0;

            virtual status handle_set_mmio_value(char* value, size_t length) = 0;

            virtual status handle_write_mmio_write_queue(char* value, size_t length) = 0;

            virtual status handle_disable_mmio_tracking() = 0;

            virtual status handle_set_code_coverage() = 0;

            virtual status handle_reset_code_coverage() = 0;

            virtual status handle_disable_code_coverage() = 0;

            virtual string handle_get_code_coverage() = 0;

            virtual char handle_get_exit_status() = 0;

            virtual status handle_do_run(std::string start_breakpoint, std::string end_breakpoint, char* mmio_data, size_t mmio_data_length) = 0;

            std::deque<status> m_event_queue;

            sem_t m_full_slots;
            sem_t m_empty_slots;

            std::thread m_interface_thread;

            test_interface* m_interface;

            test_interface::request m_current_req;
            test_interface::response m_current_res;

            mwr::u8 m_bb_array [MAP_SIZE];
            mwr::u64 m_prev_bb_loc = 0;
    };

}


#endif