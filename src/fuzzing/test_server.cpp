#include "fuzzing/test_server.h"
#include <grpcpp/server_builder.h>
#include <thread>
#include <iostream>
#include <vcml.h>
#include <fstream>
#include "fuzzing/afl-hash.h"

using grpc::Server;
using grpc::ServerContext;
using grpc::ServerBuilder;
using namespace vcml::debugging;

namespace fuzzing{


void test_gRPCserver::register_handler(const char* cmd, handler h) {
    for (const auto& other : m_handlers) {
        if (mwr::starts_with(other.first, cmd) || mwr::starts_with(cmd, other.first))
            VCML_ERROR("overlapping handlers %s %s", cmd, other.first.c_str());
    }

    m_handlers[cmd] = std::move(h);
}

int test_gRPCserver::handle_command(const string& command) {
    for (const auto& handler : m_handlers)
        if (mwr::starts_with(command, handler.first))
            return handler.second(command);
    return Status::ERROR; // command not supported
}


int test_gRPCserver::handle_continue(const string& cmd) 
{
    // Let's greenlight the other threads, we're ready to process
    sem_post(&emptySlots);

    // If the buffer is not empty we use this handle_continue()
    // execution to notify the client on previous events
    if(is_sim_suspended && exitID_buffer.empty()){
        is_sim_suspended = false;
        resume();
    }
    sem_wait(&fullSlots);

    Status exitID = exitID_buffer.front();
    exitID_buffer.pop_front();

    return static_cast<int>(exitID);
}

int test_gRPCserver::handle_kill_server(const string& cmd) 
{
    kill_server = true;
    return Status::STATUS_OK;
}

void test_gRPCserver::remove_breakpoint(mwr::u64 addr, int vector_idx)
{
    std::cout << "brk removed" << std::endl;
    for (auto* target : tgt){
        target->remove_breakpoint(addr,this);
    }

    brkpoint.erase(brkpoint.begin() + vector_idx);
}

grpc::Status test_gRPCserver::get_code_coverage(__attribute__((unused)) ServerContext* context_ptr,
                           const req_msg* req_ptr, basic_block* bb_bytes)
{
    for(auto* target : tgt)
    {
        if(!target->is_tracing_basic_blocks())
            return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, "code coverage is not set");
        
        /* std::ofstream myfile ("example.txt");
        if (myfile.is_open())
        {
            for(int count = 0; count < MAP_SIZE; count ++){
                if(bb_array[count] != 0){
                    myfile << "Element n." << count << " " << unsigned(bb_array[count]) << "\n" ;}
            }
            myfile.close();
        }*/
        std::vector<mwr::u8> v(bb_array, bb_array + sizeof bb_array / sizeof bb_array[0]);
        std::string s(v.begin(), v.end());

        //int i = 0;
        //while(i < MAP_SIZE)
        //{
            //basic_block bb_data;
            //bb_data.set_pc(s);
            bb_bytes->set_pc(s);

            //writer->Write(bb_data);
            //i++;
        //}
    }
    return grpc::Status::OK;
}

int test_gRPCserver::handle_set_code_coverage(const string& cmd)
{
    for (auto* target : target::all())
       target->trace_basic_blocks(this);
    
    return Status::STATUS_OK;
}

int test_gRPCserver::handle_rm_code_coverage(const string& cmd)
{
    for (auto* target : tgt)
       target->untrace_basic_blocks(this);
    
    return Status::STATUS_OK;
}

int test_gRPCserver::handle_get_exit_status(const string& cmd)
{
    return ret_value;
}

void test_gRPCserver::notify_basic_block(target& tgt, mwr::u64 pc, size_t blksz,
                                    size_t icount)
{
    /* This version does not perform better, it only seems slower
       Both perform vey poorly, 770 lines out of ~1.2k (amongs the ones !=0) saturated
        uint64_t curr_bb_loc = afl_hash_ip(pc) & (MAP_SIZE - 1);
        bb_array[curr_bb_loc ^ prev_bb_loc]++;
        prev_bb_loc = curr_bb_loc >> 1;
    */
    
    mwr::u64 curr_bb_loc = (pc >> 4) ^ (pc << 8);
    curr_bb_loc &= MAP_SIZE - 1;

    bb_array[curr_bb_loc ^ prev_bb_loc]++;
    prev_bb_loc = curr_bb_loc >> 1;
}

int test_gRPCserver::read_reg_value(string reg_name)
{
    int read_val;

    for (auto* target : tgt){
        const cpureg *reg = target->find_cpureg(reg_name);
        reg->read(&read_val, reg->size);
    }
    return read_val;
}

void test_gRPCserver::notify_breakpoint_hit(const breakpoint& bp) 
{   
    sem_wait(&emptySlots);

    exitID_buffer.push_back(Status::BREAKPOINT_HIT);
    if(!is_sim_suspended){
        is_sim_suspended = true;
        suspend();
    }
    sem_post(&fullSlots);

    vcml::log_info("breakpoit hit");

    mwr::u64 addr = bp.address();
    auto it = find_breakpoint(addr);

    // If we run into the exit breakpoint read the register with the result (0 success, 1 fault)
    if(it != brkpoint.end()){
        int str_eq = brkpoint[it - brkpoint.begin()].name.compare("exit");
        if(!str_eq)
            ret_value = read_reg_value("r0");
    }
    
    remove_breakpoint(bp.address(), it-brkpoint.begin());
}

int test_gRPCserver::handle_pause(const string& cmd) 
{ 
    if(!simulation_suspended()){
        suspend();
        return Status::STATUS_OK;
    } else
        return Status::ERROR;
}

int test_gRPCserver::handle_set_mmio_tracking(const string& cmd){
    mmio_access_ptr->track_mmio_access = true;
    return Status::STATUS_OK;
}

int test_gRPCserver::handle_disable_mmio_tracking(const string& cmd){
    mmio_access_ptr->track_mmio_access = false;
    return Status::STATUS_OK;
}

/*  
    With an mmio access event this function is executed
    - First it pushed the exitID in the buffer, the client is informed after sem_post()
    - In the case of a read, the simulation is stopped, waiting for the client response
*/
void test_gRPCserver::on_mmio_access(vcml::tlm_generic_payload& tx)
{
    tlm::tlm_command cmd = tx.get_command();
    unsigned char* ptr = tx.get_data_ptr();
    unsigned int length = tx.get_data_length(); // this should be 1 byte
    uint64_t mmio_addr = tx.get_address();

    sem_wait(&emptySlots);

    if(mmio_access_ptr->track_mmio_access) //Let's check the client didn't de-activate the tracking while we were waiting
    {
        if(cmd == tlm::TLM_READ_COMMAND){
            exitID_buffer.push_back(Status::MMIO_READ);
            mmio_access_ptr->read_data.length = length;
        }else
        { 
            exitID_buffer.push_back(Status::MMIO_WRITE);

            auto mmio_val = std::make_unique<unsigned char[]>(length);

            for(uint32_t i=0; i<length; i++)
                mmio_val[i]= *(ptr+i);

            mmio_access_ptr->write_data_buffer.push(MMIO_access::data{std::move(mmio_val), length, mmio_addr}); 
        }
        if(!is_sim_suspended){
            is_sim_suspended = true;
            suspend();
        }
        sem_post(&fullSlots);

        if(cmd == tlm::TLM_READ_COMMAND)
        {
            std::unique_lock lk(mmio_access_ptr->mmio_data_mtx);
            mmio_access_ptr->mmio_data_cv.wait(lk, [this]{ return mmio_access_ptr->read_data.ready; });

            mmio_access_ptr->read_data.ready = false;
            
            memcpy(ptr, mmio_access_ptr->read_data.value.get(), length);

            lk.unlock();
        }
    }
    else // if track_mmio_access is false, then release the lock
        sem_post(&emptySlots);
    
    tx.set_response_status(tlm::TLM_OK_RESPONSE);
    // If when a write comes we want to immediately block the simulation this should be enabled
    //while(is_sim_suspended);
}

void test_gRPCserver::run()
{
    grpc_thread = std::thread(&test_gRPCserver::run_gRPCserver, this);
}


test_gRPCserver::test_gRPCserver(const string& name, fuzzing::MMIO_access& mmio_access, Can_injector& can_injector):
suspender(name),
subscriber(),
mmio_access_ptr(&mmio_access),
can_injector_ptr(&can_injector)
{
    sem_init(&emptySlots, 0, 0); 
    sem_init(&fullSlots, 0, 0);

    register_handler("c", &test_gRPCserver::handle_continue);
    register_handler("p", &test_gRPCserver::handle_pause);
    register_handler("k", &test_gRPCserver::handle_kill_server);
    register_handler("mt", &test_gRPCserver::handle_set_mmio_tracking);
    register_handler("dmt", &test_gRPCserver::handle_disable_mmio_tracking);
    register_handler("tbb", &test_gRPCserver::handle_set_code_coverage);
    register_handler("rtbb", &test_gRPCserver::handle_rm_code_coverage);
    register_handler("ges", &test_gRPCserver::handle_get_exit_status);

    tgt = vcml::debugging::target::all();
    
    run();
    is_sim_suspended = true;
    suspend();
}

grpc::Status test_gRPCserver::HandleCommand(__attribute__((unused)) ServerContext* context_ptr,
                           const req_msg* req_ptr, rsp_msg* rsp_ptr)
    {
        int response;
        const auto req_command = req_ptr->req_command();
        // Add help option & add handlers
        response = handle_command(req_command);

        std::cout << "Command:" << req_command << std::endl;

        rsp_ptr->set_rsp_status(response);

        std::cout << "Response:" << response << std::endl;

        return grpc::Status::OK;
    }

std::vector<test_gRPCserver::grpc_brkpoint>::iterator test_gRPCserver::find_breakpoint(string sym_name)
{
    auto it = std::find_if(brkpoint.begin(), brkpoint.end(), 
                            [&sn = sym_name] (const grpc_brkpoint& bp)-> bool { return sn == bp.name;});
    return it;
}

std::vector<test_gRPCserver::grpc_brkpoint>::iterator test_gRPCserver::find_breakpoint(mwr::u64 sym_addr)
{
    auto it = std::find_if(brkpoint.begin(), brkpoint.end(), 
                            [&sa = sym_addr] (const grpc_brkpoint& bp)-> bool { return sa == bp.sym_addr;});
    return it;
}

grpc::Status test_gRPCserver::set_breakpoint(__attribute__((unused)) ServerContext* context_ptr,
                           const req_msg* req_ptr, rsp_msg* rsp_ptr)
{
    tgt = vcml::debugging::target::all();
    for (auto* target : tgt) {

            auto sym_name = req_ptr->req_command();
            int offset = 0;
            //Let's look for potential offset (eg main+4)
            int idx = sym_name.find("+");
            if(idx != -1){
                offset = std::stoi(sym_name.substr(idx+1,sym_name.length()-1)); //eg 4
                sym_name = sym_name.substr(0,idx); //eg main
            }
            auto it = find_breakpoint(sym_name);

            //if the breakpoint is not already set
            if(it == brkpoint.end()){

                const symbol* sym_ptr = target->symbols().find_symbol(sym_name); //get the symbol of the eg main from the symbols' list
                mwr::u64 sym_addr;

                if(sym_ptr)
                    sym_addr = sym_ptr->virt_addr() + offset; // -1 is a workaround for elf reader quirks
                else 
                    return grpc::Status(grpc::StatusCode::NOT_FOUND, "failed to retrieve the symbol");

                if(sym_addr){
                    if(target->insert_breakpoint(sym_addr-1, this)){ 
                        brkpoint.push_back({sym_ptr, sym_name, sym_addr-1});
                        return grpc::Status::OK;
                    } else
                        GRPC_SERVER_ERROR("failed to insert the breakpoint");
                } else
                    GRPC_SERVER_ERROR("failed to retrieve the symbol's virtual address");
            }
    }
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "failed to insert the breakpoint");
}

grpc::Status test_gRPCserver::remove_breakpoint(__attribute__((unused)) ServerContext* context_ptr,
                           const req_msg* req_ptr, rsp_msg* rsp_ptr)
{
    const auto sym_name = req_ptr->req_command();
    auto it = find_breakpoint(sym_name);

        if(it != brkpoint.end()){
            remove_breakpoint((*it).sym_addr, it - brkpoint.begin());
            return grpc::Status::OK;
        } else
            vcml::log_info("breakpoint not set");
        
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "failed to retrieve the symbol");
}

grpc::Status test_gRPCserver::get_MMIOvalue(__attribute__((unused)) ServerContext* context_ptr,
                           const req_msg* req_ptr, mmio_output* mmio_output_ptr)
{
    if(mmio_access_ptr->track_mmio_access) // Check that data are available & if mmio access is set
    {
        if(mmio_access_ptr->write_data_buffer.empty()){
            return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, "no values to be read");}

        mmio_output_ptr->set_addr(mmio_access_ptr->write_data_buffer.front().addr);

        
        string output_str = "";
        int len = mmio_access_ptr->write_data_buffer.front().length;
        for(int i=(len-1); i >= 0; i--){
            std::cout << static_cast<unsigned>(mmio_access_ptr->write_data_buffer.front().value[i]) << std::endl;
            output_str.append(string(1, static_cast<char>(mmio_access_ptr->write_data_buffer.front().value[i])));
        }
        
        mmio_output_ptr->set_value(output_str);
        mmio_access_ptr->write_data_buffer.pop();

        return grpc::Status::OK;
    }
    else //Command execution failed
        return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, "mmio access is not set");
}


grpc::Status test_gRPCserver::set_MMIOvalue(__attribute__((unused)) ServerContext* context_ptr,
                           const mmio_input* mmio_input_ptr, rsp_msg* rsp_ptr)
{
    std::unique_lock lk(mmio_access_ptr->mmio_data_mtx);
    
    std::cout << mmio_input_ptr->value() << std::endl;
    
    int fuz_len = mmio_input_ptr->length();
    mmio_access_ptr->read_data.length = fuz_len;

    auto uchar_arr =  std::make_unique<unsigned char[]>(fuz_len);

    // copy the data in an unsigned array and then to the field value of the read_data struct
    for(int i=0; i< fuz_len; i++)
        uchar_arr[i] = static_cast<const unsigned char>(*(mmio_input_ptr->value().data()+i));

    mmio_access_ptr->read_data.value = std::move(uchar_arr);

    mmio_access_ptr->read_data.ready = true;
    lk.unlock();
    mmio_access_ptr->mmio_data_cv.notify_one();

    // The fuzzer is sending us data, it means we're testing a driver
    // Call send_to_guest() of the can_injector, but before fill in the field of the frame
    if(!mmio_access_ptr->track_mmio_access){

        vcml::can_frame can_msg = {16, 2, 0, {1, 2}}; //id, dlc, flags, data
        can_injector_ptr->send_to_guest(can_msg);
    }

    return grpc::Status::OK;
}

void test_gRPCserver::run_gRPCserver()
{
    std::string server_address("0.0.0.0:50051");
    ServerBuilder builder;

    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(this);
    server = builder.BuildAndStart();

    std::cout << "Server listening on " << server_address << std::endl;
    server->Wait();
}

#pragma GCC push_options
#pragma GCC optimize("O0")
void test_gRPCserver::notify_vp_finished()
{
    sem_wait(&emptySlots);
    exitID_buffer.push_back(Status::VP_END);
    sem_post(&fullSlots);

    while(!kill_server);
}
#pragma GCC pop_options

test_gRPCserver::~test_gRPCserver(){
    sem_destroy(&emptySlots);
    sem_destroy(&fullSlots);

}

}//namespace fuzzing 