#ifndef TestReceiver_h
#define TestReceiver_h

#define LOG_INFO(fmt, ...) vcml::log_info("FUZZ_INTERFACE: " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) vcml::log_error("FUZZ_INTERFACE: " fmt, ##__VA_ARGS__)

#include <semaphore.h>
#include "vcml/debugging/suspender.h"
#include "vcml/debugging/subscriber.h"
#include "vcml/debugging/target.h"
#include "vcml/core/types.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>
#include <thread>

#include "probe.h"
#include "can_injector.h"

using namespace vcml::debugging;
using std::string;

#define REQUEST_LENGTH 256
#define RESPONSE_LENGTH 256

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)

namespace fuzzing{

    class TestReceiver final: public suspender, public subscriber{

        public:

            enum Command{
                CONTINUE, KILL, SET_BREAKPOINT, REMOVE_BREAKPOINT, SET_MMIO_TRACKING, DISABLE_MMIO_TRACKING, SET_MMIO_VALUE, SET_CODE_COVERAGE, REMOVE_CODE_COVERAGE, GET_CODE_COVERAGE, GET_EXIT_STATUS
            };

            enum Status {
                STATUS_OK, MMIO_READ, MMIO_WRITE, VP_END, BREAKPOINT_HIT, ERROR=-1
            };
            
            struct Request{
                Command command;
                char data[REQUEST_LENGTH-1];
                size_t dataLength = 0;
            };

            struct Response{
                char data[RESPONSE_LENGTH];
                size_t dataLength = 0;
            };

            struct Breakpoint{
                const symbol* ptr;
                string name;
                mwr::u64 addr;
            };

            TestReceiver(const string& name, MMIO_access& mmio_access, Can_injector& can_injector);

            ~TestReceiver();

            void run();

            void notify_breakpoint_hit(const breakpoint& bp) override;

            void notify_basic_block(target& tgt, mwr::u64 pc, size_t blksz, size_t icount) override;

            void on_mmio_access(vcml::tlm_generic_payload& tx);

            void notify_vp_finished();

            char readRegValue(string reg_name);

        private:
    
            void messageReceiver();

            void handleCommand(Request* request, Response* response);

            Status handleContinue();

            Status handleKill();

            std::vector<Breakpoint>::iterator find_breakpoint(string name);
            std::vector<Breakpoint>::iterator find_breakpoint(mwr::u64 addr);

            Status handleSetBreakpoint(string symbol, int offset);

            Status handleRemoveBreakpoint(string sym_name);

            void removeBreakpoint(mwr::u64 addr, int vector_idx);

            Status handleSetMMIOTracking();

            Status handleDisableMMIOTracking();

            Status handleSetMMIOValue(char* value, size_t length);

            Status handleSetCodeCoverage();

            Status handleDisableCodeCoverage();

            std::string handleGetCodeCoverage();

            char handleGetExitStatus();

            std::thread interface_thread;

            MMIO_access* mmio_access_ptr;
            Can_injector* can_injector_ptr;

            sem_t fullSlots, emptySlots;
            std::deque<Status> exitID_buffer;

            mq_attr attr;
            mqd_t mqt_requests, mqt_responses;

            bool is_sim_suspended = false;

            std::vector<Breakpoint> active_breakpoints;  

            char ret_value = 0;

            bool kill_server = false;

            mwr::u8 bb_array [MAP_SIZE];
            mwr::u64 prev_bb_loc = 0;

            char buffer[REQUEST_LENGTH]; // Buffer should match mq_msgsize
            ssize_t bytes_read;

    };

};

#endif