#include "testing/test_receiver.h"

using namespace vcml::debugging;

namespace testing{

    test_receiver::test_receiver(const string& name, probe& get_probe, testing::MMIO_access& mmio_access, Can_injector& can_injector):
        suspender(name),
        subscriber(),
        m_probe(&get_probe),
        m_mmio_access(&mmio_access),
        m_can_injector(&can_injector),
        m_enabled_option("--enable-test-receiver", "Enables the test-receiver to automatically run tests inside avp64."),
        m_communication_option("--test-receiver-interface", "Sets the interfacing method of the test receiver. 0: Message queues, 1: pipes."),
        m_mq_request_option("--test-receiver-mq-request", "File descriptor of the message queue where requests are read from. Required for interface 0."),
        m_mq_response_option("--test-receiver-mq-response", "File descriptor of the message queue where responses are send to. Required for interface 0."),
        m_pipe_request_option("--test-receiver-pipe-request", "File descriptor of the pipe where requests are read from. Required for interface 1."),
        m_pipe_response_option("--test-receiver-pipe-response", "File descriptor of the pipe where responses are send to. Required for interface 1.") {

            sem_init(&m_empty_slots, 0, 0); 
            sem_init(&m_full_slots, 0, 0);
        }

    test_receiver::~test_receiver(){
        sem_destroy(&m_empty_slots);
        sem_destroy(&m_full_slots);

        if(m_current_req.data != nullptr) free(m_current_req.data);
        if(m_current_res.data != nullptr) free(m_current_res.data);

        delete m_interface;
    }

    void test_receiver::parse_args(int argc, const char* const* argv){
        m_enabled_option.parse(argc, argv);
        m_communication_option.parse(argc, argv);
        m_mq_request_option.parse(argc, argv);
        m_mq_response_option.parse(argc, argv);
        m_pipe_request_option.parse(argc, argv);
        m_pipe_response_option.parse(argc, argv);
    }

    void test_receiver::run(){

        // Dont start the test receiver if the option --enable-test-receiver is not set.
        if(!m_enabled_option.has_value() || !m_enabled_option.value()) return;

        LOG_INFO("Test receiver enabled!");

        m_is_sim_suspended = true;
        suspend();

        test_interface::interface selected_interface = test_interface::MQ;

        if(m_communication_option.has_value()){
            try{
                selected_interface = (test_interface::interface)std::stoi(m_communication_option.value());
            }catch(std::exception &e){
                LOG_ERROR("Selected interface (--test-receiver-interface) is not valid number.");
            }

            if(selected_interface >= test_interface::INTERFACE_COUNT){
               LOG_ERROR("Selected interface (--test-receiver-interface) is invalid. Possible selection 0-%d.", test_interface::INTERFACE_COUNT-1); 
            }

        }
        
        if(selected_interface == test_interface::MQ){

            if(!m_mq_request_option.has_value() || !m_mq_response_option.has_value()){
                LOG_ERROR("In order to use MQ for communication --test-receiver-mq-request and --test-receiver-mq-response must be set!"); 
                exit(1);
            }

            //m_interface = new mq_test_interface("/avp64-test-receiver", "/avp64-test-sender");
            m_interface = new mq_test_interface(m_mq_request_option.value(), m_mq_response_option.value());

            LOG_INFO("Interface MQ selected for communication with fd %s and %s.", m_mq_request_option.value().c_str(), m_mq_response_option.value().c_str());  
        }else if(selected_interface == test_interface::PIPE){

            if(!m_pipe_request_option.has_value() || !m_pipe_response_option.has_value()){
                LOG_ERROR("In order to use pipes for communication --test-receiver-pipe-request and --test-receiver-pipe-response must be set!"); 
                exit(1);
            }

            int pipe_request = -1;
            int pipe_response = -1;
            
            try{
                pipe_request = std::stoi(m_pipe_request_option.value());
                pipe_response = std::stoi(m_pipe_response_option.value());
            }catch(std::exception &e){
                LOG_ERROR("specified pipes (--test-receiver-pipe-request or --test-receiver-pipe-response) are not valid numbers.");
            }

            m_interface = new pipe_test_interface(pipe_request, pipe_response);   
            LOG_INFO("Interface pipes selected for communication with fd %d and %d.", pipe_request, pipe_response);  
        }

        if(!m_interface->start()){
            LOG_ERROR("Error starting communication interface!"); 
            exit(1);
        }
        

        m_interface_thread = std::thread([this] {
            this->receiver();
        });

    }

    void test_receiver::receiver() {

        while (true) {

            if(m_interface->receive_request()){

                m_current_req = m_interface->get_request();
                m_current_res = mq_test_interface::response();

                LOG_INFO("Successfully received request with command: %d", (uint8_t)m_current_req.cmd);

                //Handling request
                handle_request(&m_current_req, &m_current_res);

                if(m_interface->send_response(m_current_res)){
                    LOG_INFO("Successfully sent response for command: %d", (uint8_t)m_current_req.cmd);
                }else{
                    LOG_ERROR("Could not send response for command: %d", (uint8_t)m_current_req.cmd);
                }

                //Clearing response data. Request data is cleared by m_interface.
                if(m_current_res.data != nullptr){
                    free(m_current_res.data);
                    m_current_res.data = nullptr;
                }
            }
        }
    }

    void test_receiver::handle_request(test_interface::request* req, test_interface::response* res){

        switch(req->cmd){

            case test_interface::CONTINUE:
            {
                res->data = (char*)malloc(1);
                res->data[0] = handle_continue();
                res->data_length = 1;
                break;
            }

            case test_interface::KILL:
            {
                res->data = (char*)malloc(1);
                res->data[0] = handle_kill();
                res->data_length = 1;
                break;
            }

            case test_interface::SET_BREAKPOINT:
            {
                uint8_t offset = req->data[0];
                string symbol_name(req->data + 1, req->data_length-1);

                res->data = (char*)malloc(1);
                res->data[0] = handle_set_breakpoint(symbol_name, offset);
                res->data_length = 1;
                break;
            }

            case test_interface::REMOVE_BREAKPOINT:
            {
                string symbol_name(req->data, req->data_length);

                res->data = (char*)malloc(1);
                res->data[0] = handle_remove_breakpoint(symbol_name);
                res->data_length = 1;
                break;
            }

            case test_interface::SET_MMIO_TRACKING:
            {
                res->data = (char*)malloc(1);
                res->data[0] = handle_set_mmio_tracking();
                res->data_length = 1;
                break;
            }

            case test_interface::DISABLE_MMIO_TRACKING:
            {
                res->data = (char*)malloc(1);
                res->data[0] = handle_disable_mmio_tracking();
                res->data_length = 1;
                break;
            }

            case test_interface::SET_MMIO_VALUE:
            {   
                res->data = (char*)malloc(1);
                res->data[0] = handle_set_mmio_value(&req->data[1], req->data[0]);
                res->data_length = 1;
                break;
            }

            case test_interface::SET_CODE_COVERAGE:
            {
                res->data = (char*)malloc(1);
                res->data[0] = handle_set_code_coverage();
                res->data_length = 1;
                break;
            }

            case test_interface::RESET_CODE_COVERAGE:
            {
                res->data = (char*)malloc(1);
                res->data[0] = handle_reset_code_coverage();
                res->data_length = 1;
                break;
            }

            case test_interface::REMOVE_CODE_COVERAGE:
            {
                res->data = (char*)malloc(1);
                res->data[0] = handle_disable_code_coverage();
                res->data_length = 1;
                break;
            }

            case test_interface::GET_CODE_COVERAGE:
            {
                string coverage = handle_get_code_coverage();
                
                uint32_t length = coverage.size();

                res->data = (char*)malloc(coverage.size()+4);
                res->data[0] = (char)(length & 0xFF);
                res->data[1] = (char)((length >> 8) & 0xFF);
                res->data[2] = (char)((length >> 16) & 0xFF);
                res->data[3] = (char)((length >> 24) & 0xFF);

                memcpy(res->data+4, coverage.c_str(), coverage.size());
                res->data_length = coverage.size();
                break;
            }

            case test_interface::GET_EXIT_STATUS:
            {   
                res->data = (char*)malloc(1);
                res->data[0] = handle_get_exit_status();
                res->data_length = 1;
                break;
            }

            case test_interface::DO_RUN:
            {

                // Data:
                // Length start breakpoint +
                // Start breakpoint name +
                // Length end breakpoint +
                // End breakpoint name +
                // Length input +
                // Input +

                //TODO here also unsigned int ?
                //Termination character ?
                //Length checking !!!!!!!!!!

                int start_breakpoint_length = req->data[0];
                string start_breakpoint(&req->data[1], start_breakpoint_length);

                int end_breakpoint_length = req->data[start_breakpoint_length+1];
                string end_breakpoint(&req->data[start_breakpoint_length+2], end_breakpoint_length);

                unsigned int input_length = ((int)(unsigned char)req->data[start_breakpoint_length+end_breakpoint_length+2]) | ((int)(unsigned char)req->data[start_breakpoint_length+end_breakpoint_length+3] << 8) | ((int)(unsigned char)req->data[start_breakpoint_length+end_breakpoint_length+4] << 16) | ((int)(unsigned char)req->data[start_breakpoint_length+end_breakpoint_length+5] << 24);

                res->data = (char*)malloc(1);
                res->data[0] = handle_do_run(start_breakpoint, end_breakpoint, &req->data[start_breakpoint_length+end_breakpoint_length+6], input_length);
                res->data_length = 1;
                break;
            }

            case test_interface::DO_RUN_SHM:
            {

                // Data:
                // Length start breakpoint +
                // Start breakpoint name +
                // Length end breakpoint +
                // End breakpoint name +
                // MMIO data shared memory ID +
                // SHM offset

                int start_breakpoint_length = req->data[0];
                string start_breakpoint(&req->data[1], start_breakpoint_length);

                int end_breakpoint_length = req->data[start_breakpoint_length+1];
                string end_breakpoint(&req->data[start_breakpoint_length+2], end_breakpoint_length);

                int shm_id = ((int)(unsigned char)req->data[start_breakpoint_length+end_breakpoint_length+2]) | ((int)(unsigned char)req->data[start_breakpoint_length+end_breakpoint_length+3] << 8) | ((int)(unsigned char)req->data[start_breakpoint_length+end_breakpoint_length+4] << 16) | ((int)(unsigned char)req->data[start_breakpoint_length+end_breakpoint_length+5] << 24);

                unsigned int offset = ((int)(unsigned char)req->data[start_breakpoint_length+end_breakpoint_length+6]) | ((int)(unsigned char)req->data[start_breakpoint_length+end_breakpoint_length+7] << 8) | ((int)(unsigned char)req->data[start_breakpoint_length+end_breakpoint_length+8] << 16) | ((int)(unsigned char)req->data[start_breakpoint_length+end_breakpoint_length+9] << 24);

                res->data = (char*)malloc(1);
                res->data[0] = handle_do_run_shm(start_breakpoint, end_breakpoint, shm_id, offset);
                res->data_length = 1;
                break;
            }

            case test_interface::WRITE_CODE_COVERAGE:
            {
                int shm_id = ((int)(unsigned char)req->data[0]) | ((int)(unsigned char)req->data[1] << 8) | ((int)(unsigned char)req->data[2] << 16) | ((int)(unsigned char)req->data[3] << 24);
                unsigned int offset = ((int)(unsigned char)req->data[4]) | ((int)(unsigned char)req->data[5] << 8) | ((int)(unsigned char)req->data[6] << 16) | ((int)(unsigned char)req->data[7] << 24);

                res->data = (char*)malloc(1);
                res->data[0] = handle_write_code_coverage(shm_id, offset);
                res->data_length = 1;

                break;
            }

            default:
            {
                LOG_INFO("Command %d not found!", req->cmd);
                break;
            }

        }
    }

    test_receiver::status test_receiver::handle_continue(){
        // Let's greenlight the other threads, we're ready to process
        sem_post(&m_empty_slots);

        // If the buffer is not empty we use this handle_continue()
        // execution to notify the client on previous events
        if(m_is_sim_suspended && m_exit_id_buffer.empty()){
            m_is_sim_suspended = false;
            resume();
        }

        //Wait until next suspending.
        sem_wait(&m_full_slots);

        //Sending the reason of the suspending.
        status exit_id = m_exit_id_buffer.front();
        m_exit_id_buffer.pop_front();

        LOG_INFO("Event: %d", exit_id);

        return exit_id;
    }

    test_receiver::status test_receiver::handle_kill(){
        LOG_INFO("Killing.");
        m_kill_server = true;
        return STATUS_OK;
    }

    std::vector<test_receiver::breakpoint>::iterator test_receiver::find_breakpoint(string name){
        auto it = std::find_if(m_active_breakpoints.begin(), m_active_breakpoints.end(), 
                                [&sn = name] (const breakpoint& bp)-> bool { return sn == bp.name;});
        return it;
    }

    std::vector<test_receiver::breakpoint>::iterator test_receiver::find_breakpoint(mwr::u64 addr){
        auto it = std::find_if(m_active_breakpoints.begin(), m_active_breakpoints.end(), 
                                [&sa = addr] (const breakpoint& bp)-> bool { return sa == bp.addr;});
        return it;
    }

    test_receiver::status test_receiver::handle_set_breakpoint(string &sym_name, int offset) {

        for (auto* target : target::all()) {

            auto it = find_breakpoint(sym_name);

            //if the breakpoint is not already set
            if(it == m_active_breakpoints.end()){

                const symbol* sym_ptr = target->symbols().find_symbol(sym_name); //get the symbol of the eg main from the symbols' list
                mwr::u64 sym_addr;

                if(sym_ptr)
                    sym_addr = sym_ptr->virt_addr() + offset; // -1 is a workaround for elf reader quirks
                else 
                    return ERROR;

                if(sym_addr){
                    if(target->insert_breakpoint(sym_addr, this)){ 
                        m_active_breakpoints.push_back({sym_ptr, sym_name, sym_addr});
                        LOG_INFO("Breakpoint set to %s with offset %d.", sym_name.c_str(), offset);
                        return STATUS_OK;
                    } else
                        LOG_ERROR("Failed to insert the breakpoint");
                } else
                    LOG_ERROR("Failed to retrieve the symbol's virtual address!");
            }
        }

        return STATUS_OK;
    }

    //Vielleicht noch offset mit rein !?
    test_receiver::status test_receiver::handle_remove_breakpoint(string &sym_name){
        
        auto it = find_breakpoint(sym_name);

        if(it != m_active_breakpoints.end()){
            remove_breakpoint((*it).addr, it - m_active_breakpoints.begin());

            return STATUS_OK;
        } else
            LOG_ERROR("Breakpoint was not set!");
        
        return ERROR;
    }

    void test_receiver::remove_breakpoint(mwr::u64 addr, int vector_idx)
    {
        for (auto* target : target::all()){
            target->remove_breakpoint(addr,this);
        }

        m_active_breakpoints.erase(m_active_breakpoints.begin() + vector_idx);
        LOG_INFO("Breakpoint removed.");
    }

    test_receiver::status test_receiver::handle_set_mmio_tracking(){
        m_mmio_access->track_mmio_access = true;
        LOG_INFO("MMIO tracking enabled.");
        return STATUS_OK;
    }

    test_receiver::status test_receiver::handle_disable_mmio_tracking(){
        m_mmio_access->track_mmio_access = false;
        LOG_INFO("MMIO tracking disabled.");
        return STATUS_OK;
    }

    test_receiver::status test_receiver::handle_set_code_coverage()
    {
        for (auto* target : target::all())
            target->trace_basic_blocks(this);
        LOG_INFO("Code coverage enabled.");
        return STATUS_OK;
    }

    test_receiver::status test_receiver::handle_reset_code_coverage()
    {
        memset(m_bb_array, 0, MAP_SIZE*sizeof(mwr::u8));
        return STATUS_OK;
    }

    test_receiver::status test_receiver::handle_disable_code_coverage()
    {
        for (auto* target : target::all())
            target->untrace_basic_blocks(this);
        LOG_INFO("Code coverage disabled.");
        return STATUS_OK;
    }

    std::string test_receiver::handle_get_code_coverage()
    {
        //TODO multiple targets ?
        //TODO is_tracing_basic_blocks not implemented ? 

        /*
        LOG_INFO("Getting code coverage.");
        for(auto* target : target::all())
        {
            if(!target->is_tracing_basic_blocks()){
                LOG_ERROR("Code coverage is not set!");
                return "";
            }
            
            std::vector<mwr::u8> v(bb_array, bb_array + sizeof bb_array / sizeof bb_array[0]);
            std::string s(v.begin(), v.end());

            return s;

        }
    
        return "";
        */

        std::vector<mwr::u8> v(m_bb_array, m_bb_array + sizeof m_bb_array / sizeof m_bb_array[0]);
        std::string s(v.begin(), v.end());
        return s;
    }

    void test_receiver::notify_basic_block(target& tgt, mwr::u64 pc, size_t blksz, size_t icount)
    {
        //LOG_INFO("Basic block notification.");
        
        mwr::u64 curr_bb_loc = (pc >> 4) ^ (pc << 8);
        curr_bb_loc &= MAP_SIZE - 1;

        m_bb_array[curr_bb_loc ^ m_prev_bb_loc]++;
        m_prev_bb_loc = curr_bb_loc >> 1;
    }

    char test_receiver::handle_get_exit_status()
    {   
        LOG_INFO("Getting return code of %d.", m_ret_value);
        return m_ret_value;
    }

    test_receiver::status test_receiver::handle_do_run(std::string start_breakpoint, std::string end_breakpoint, char* mmio_data, size_t mmio_data_length)
    {   
        
        LOG_INFO("Start breakpoint %s, end %s", start_breakpoint.c_str(), end_breakpoint.c_str());
    

        if(mmio_data[mmio_data_length-1] == '\0'){
            LOG_INFO("Loaded test case: %s.", mmio_data);
        }else{
            LOG_INFO("Could not print test case, because there is not a termination character.");
        }

        LOG_INFO("Setting end breakpoint.");
        handle_set_breakpoint(end_breakpoint, 0);

        size_t mmio_data_index = 0;

        m_probe->set_read_queue(mmio_data, mmio_data_length);

        status last_status = handle_continue();

        while(true){

            if(last_status == VP_END){
                LOG_INFO("Run loop: VP_END.");
                break;
            }else if(last_status == MMIO_READ){
                LOG_INFO("Run loop: MMIO_READ.");

                if(mmio_data_index < mmio_data_length+1){
                    
                    LOG_INFO("Run loop: Setting MMIO value %c", mmio_data[mmio_data_index]);

                    last_status = handle_set_mmio_value(&mmio_data[mmio_data_index], 1);
                    mmio_data_index ++;

                }else{
                    LOG_INFO("Run loop: ERROR! More data requested!");
                    char zero = 0;
                    last_status = handle_set_mmio_value(&zero, 1);
                }

            }else if(last_status == BREAKPOINT_HIT){
                LOG_INFO("Run loop: Breakpoint hit.");
                break;
            }else{
                LOG_INFO("Run loop: Other");
                last_status = handle_continue();
            }
        }

        //TODO hangle: VP_END

        LOG_INFO("Setting start breakpoint.");
        handle_set_breakpoint(start_breakpoint, 0);

        LOG_INFO("Continuing until start breakpoint.");

        //TODO: VP_END !?
        while(true){
            last_status = handle_continue();
            if(last_status == BREAKPOINT_HIT){
                break;
            }
        }

        return STATUS_OK;
    }

    test_receiver::status test_receiver::handle_do_run_shm(std::string start_breakpoint, std::string end_breakpoint, int shm_id, unsigned int offset)
    {
        LOG_INFO("Loading MMIO data from shared memory %d.", shm_id);

        // Attach the shared memory segment to the process's address space
        // Using shared memory directly for better performance. Copying would be safer, but we want performance here.
        char* mmio_data = static_cast<char*>(shmat(shm_id, nullptr, SHM_RDONLY));
        if (mmio_data == reinterpret_cast<char*>(-1)) {
            LOG_ERROR("Failed to attach shared memory segment: %s", strerror(errno));
            return ERROR;
        }

        struct shmid_ds shm_info;
        if (shmctl(shm_id, IPC_STAT, &shm_info) == -1) {
            LOG_ERROR("Reading length of shared memory failed!");
            return ERROR;
        }

        size_t data_length = shm_info.shm_segsz-offset;

        test_receiver::status return_status = handle_do_run(start_breakpoint, end_breakpoint, mmio_data+offset, data_length);

        // Detach the shared memory
        if (shmdt(mmio_data) == -1) {
            LOG_ERROR("Failed to detach shared memory: %s", strerror(errno));
            // Continue to return the read data even if detaching fails
        }

        return return_status;
    }

    void test_receiver::notify_breakpoint_hit(const vcml::debugging::breakpoint& bp){
        sem_wait(&m_empty_slots);

        m_exit_id_buffer.push_back(status::BREAKPOINT_HIT);
        if(!m_is_sim_suspended){
            m_is_sim_suspended = true;
            suspend();
        }
        sem_post(&m_full_slots);

        mwr::u64 addr = bp.address();
        auto it = find_breakpoint(addr);

        // If we run into the exit breakpoint read the register with the result (0 success, 1 fault)
        if(it != m_active_breakpoints.end()){
            LOG_INFO("Breakpoit %s hit.", it->name.c_str());
            
            if(!it->name.compare("exit")){
                m_ret_value = read_reg_value("x0");
                LOG_INFO("Exit return value: %d.", m_ret_value);
            }
        
            remove_breakpoint(bp.address(), it-m_active_breakpoints.begin());
        }
    }

    char test_receiver::read_reg_value(string reg_name)
    {
        int read_val;

        for (auto* target : target::all()){
            const cpureg *reg = target->find_cpureg(reg_name);
            reg->read(&read_val, reg->size);
        }

        //TODO need to change!
        return (char)read_val;
    }

    //#pragma GCC push_options
    //#pragma GCC optimize("O0")
    void test_receiver::notify_vp_finished()
    {
        LOG_INFO("VP finished.");
        sem_wait(&m_empty_slots);
        m_exit_id_buffer.push_back(status::VP_END);
        sem_post(&m_full_slots);

        LOG_INFO("Waiting for kill request.");
        while(!m_kill_server);
    }
    //#pragma GCC pop_options

    void test_receiver::on_mmio_access(vcml::tlm_generic_payload& tx)
    {
        LOG_INFO("MMIO access event.");

        tlm::tlm_command cmd = tx.get_command();
        unsigned char* ptr = tx.get_data_ptr();
        unsigned int length = tx.get_data_length(); // this should be 1 byte
        uint64_t mmio_addr = tx.get_address();

        sem_wait(&m_empty_slots);

        if(m_mmio_access->track_mmio_access) //Let's check the client didn't de-activate the tracking while we were waiting
        {
            if(cmd == tlm::TLM_READ_COMMAND){
                m_exit_id_buffer.push_back(status::MMIO_READ);
                m_mmio_access->read_data.length = length;
            }else
            { 
                m_exit_id_buffer.push_back(status::MMIO_WRITE);

                auto mmio_val = std::make_unique<unsigned char[]>(length);

                for(uint32_t i=0; i<length; i++)
                    mmio_val[i]= *(ptr+i);

                m_mmio_access->write_data_buffer.push(MMIO_access::data{std::move(mmio_val), length, mmio_addr}); 
            }
            if(!m_is_sim_suspended){
                m_is_sim_suspended = true;
                suspend();
            }
            sem_post(&m_full_slots);

            if(cmd == tlm::TLM_READ_COMMAND)
            {
                std::unique_lock lk(m_mmio_access->mmio_data_mtx);
                m_mmio_access->mmio_data_cv.wait(lk, [this]{ return m_mmio_access->read_data.ready; });

                m_mmio_access->read_data.ready = false;
                
                memcpy(ptr, m_mmio_access->read_data.value.get(), length);

                lk.unlock();
            }
        }
        else // if track_mmio_access is false, then release the lock
            sem_post(&m_empty_slots);
        
        tx.set_response_status(tlm::TLM_OK_RESPONSE);
        // If when a write comes we want to immediately block the simulation this should be enabled
        //while(is_sim_suspended);
    }

    test_receiver::status test_receiver::handle_set_mmio_value(char* value, size_t length)
    {
        LOG_INFO("Writing MMIO value of length %d.", (int)length);

        std::unique_lock lk(m_mmio_access->mmio_data_mtx);
        
        m_mmio_access->read_data.length = length;

        auto uchar_arr =  std::make_unique<unsigned char[]>(length);
        for(size_t i=0; i<length; i++)
            uchar_arr[i] = value[i];

        m_mmio_access->read_data.value = std::move(uchar_arr);

        m_mmio_access->read_data.ready = true;
        lk.unlock();
        m_mmio_access->mmio_data_cv.notify_one();

        return STATUS_OK;
    }

    test_receiver::status test_receiver::handle_write_code_coverage(int shm_id, unsigned int offset)
    {
        LOG_INFO("Writing Code Coverage to %d with offset %d.", shm_id, offset);

        // Attach the shared memory segment
        char* shm_addr = static_cast<char*>(shmat(shm_id, nullptr, 0));
        if (shm_addr == reinterpret_cast<char*>(-1)) {
            LOG_ERROR("Failed to attach code coverage shared memory: %s", strerror(errno));
            return ERROR;
        }

        struct shmid_ds shm_info;
        if (shmctl(shm_id, IPC_STAT, &shm_info) == -1) {
            LOG_ERROR("Reading length of coverage shared memory failed!");
            return ERROR;
        }

        if(MAP_SIZE*sizeof(mwr::u8) > (size_t)shm_info.shm_segsz-offset){
            LOG_ERROR("Coverage map does not fit into the shared memory!");
            return ERROR;
        }

        // Write the data to the shared memory
        std::memcpy(shm_addr+offset, m_bb_array, MAP_SIZE*sizeof(mwr::u8));

        // Detach the shared memory
        if (shmdt(shm_addr) == -1) {
            LOG_ERROR("Failed to detach code coverage shared memory: %s", strerror(errno));
            return ERROR;
        }

        return STATUS_OK;
    }

};