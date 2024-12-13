#ifndef VCML_GRPC_SERVER_H
#define VCML_GRPC_SERVER_H

#include <condition_variable> 
#include <queue>
#include <thread>
#include <semaphore.h>
#include <mutex> 
#include <string>
#include <grpcpp/grpcpp.h>
#include "test.grpc.pb.h"
#include "test.pb.h"
#include "vcml/debugging/suspender.h"
#include "vcml/debugging/subscriber.h"
#include "vcml/core/types.h"
#include "vcml/core/systemc.h"
#include "vcml/protocols/can.h"
#include "probe.h"
#include "can_injector.h"

#include "vcml/core/component.h"
#include "vcml/protocols/tlm.h"

#include "avp64/cpu.h"

#define GRPC_SERVER_ERROR(...)                                 \
    do {                                               \
        fprintf(stderr, "%s:%d ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__);                  \
        fprintf(stderr, "\n");                         \
        fflush(stderr);                                \
        ::exit(1);                                     \
    } while (0)

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)

using grpc::ServerContext;
using grpc::ServerBuilder;
using namespace vcml::debugging;
using std::string;

namespace fuzzing{

// This class implements the generated TestServer::Service interface
class test_gRPCserver final : public TestService::Service, public suspender, public subscriber
{
    public:
        typedef std::function<int(const string&)> handler; //pointer to a function that takes a string& as par.

    private:
        std::thread grpc_thread, mmio_thread;
        std::vector<target*> tgt;
        std::map<string, handler> m_handlers;
        int ret_value;

        struct grpc_brkpoint{
            const symbol* sym_ptr;
            string name;
            mwr::u64 sym_addr;
        };

        bool kill_server = false;
        MMIO_access* mmio_access_ptr;
        Can_injector* can_injector_ptr;
        bool is_sim_suspended = false;

        enum Status {STATUS_OK, MMIO_READ, MMIO_WRITE, VP_END, BREAKPOINT_HIT, ERROR=-1};
        sem_t fullSlots, emptySlots;
        std::deque<Status> exitID_buffer;

        void remove_breakpoint(mwr::u64 addr, int vector_idx);
        int read_reg_value(string reg_name);
        void run();
        std::vector<grpc_brkpoint>::iterator find_breakpoint(string sym_name);
        std::vector<grpc_brkpoint>::iterator find_breakpoint(mwr::u64 sym_addr);

    public:

        std::vector<grpc_brkpoint> brkpoint;  

        mwr::u8 bb_array [MAP_SIZE];
        mwr::u64 prev_bb_loc = 0;

        std::unique_ptr<grpc::Server> server;
        test_gRPCserver(const string& name, MMIO_access& mmio_access, Can_injector& can_injector);

        grpc::Status HandleCommand(__attribute__((unused)) ServerContext* context_ptr,
                           const req_msg* req_ptr, rsp_msg* rsp_ptr) override;     
        grpc::Status set_breakpoint(__attribute__((unused)) ServerContext* context_ptr,
                           const req_msg* req_ptr, rsp_msg* rsp_ptr) override; 
        grpc::Status remove_breakpoint(__attribute__((unused)) ServerContext* context_ptr,
                           const req_msg* req_ptr, rsp_msg* rsp_ptr) override;
        grpc::Status get_MMIOvalue(__attribute__((unused)) ServerContext* context_ptr,
                           const req_msg* req_ptr, mmio_output* mmio_output_ptr) override;
        grpc::Status set_MMIOvalue(__attribute__((unused)) ServerContext* context_ptr,
                           const mmio_input* mmio_input_ptr, rsp_msg* rsp_ptr) override;
        grpc::Status get_code_coverage(__attribute__((unused)) ServerContext* context_ptr,
                           const req_msg* req_ptr, basic_block* bb_bytes) override;

        void on_mmio_access(vcml::tlm_generic_payload& tx);
        template <typename T>
        void register_handler(const char* cmd, int (T::*func)(const string&));

        void register_handler(const char* command, handler handler);
        int handle_command(const string& command);

        int handle_continue(const string& cmd);
        int handle_pause(const string& cmd);
        int handle_kill_server(const string& cmd);

        virtual void notify_breakpoint_hit(const breakpoint& bp) override;

        int handle_set_mmio_tracking(const string& cmd);
        int handle_disable_mmio_tracking(const string& cmd);

        int handle_set_code_coverage(const string& cmd);
        int handle_rm_code_coverage(const string& cmd);
        int handle_get_exit_status(const string& cmd);
        virtual void notify_basic_block(target& tgt, mwr::u64 pc, size_t blksz,
                                    size_t icount) override;

        void notify_vp_finished();

        void run_gRPCserver();

        ~test_gRPCserver();
};

template <typename HOST>
void test_gRPCserver::register_handler(const char* command,
                                 int (HOST::*handler)(const string&)) {
    HOST* host = dynamic_cast<HOST*>(this);
    VCML_ERROR_ON(!host, "command host not found");
    register_handler(command, [host, handler](const string& args) -> int {
        return (host->*handler)(args);
    });
}

} // namespace fuzzing

#endif