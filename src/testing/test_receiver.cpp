#include "testing/test_receiver.h"

using namespace vcml::debugging;

namespace testing{

    test_receiver::test_receiver(){
        sem_init(&m_empty_slots, 0, 0); 
        sem_init(&m_full_slots, 0, 0);
    }

    test_receiver::~test_receiver(){
        sem_destroy(&m_empty_slots);
        sem_destroy(&m_full_slots);

        if(m_current_req.data != nullptr) free(m_current_req.data);
        if(m_current_res.data != nullptr) free(m_current_res.data);

        if(m_interface != nullptr) delete m_interface;
    }

    bool test_receiver::start(test_interface* interface){
        if(interface == nullptr){
            return false;
        }
        
        m_interface = interface;

        return true;
    }

    bool test_receiver::start_receiver_in_thread(){
        log_info_message("Receiver thread starting.");
        m_interface_thread = std::thread([this] {
            this->receiver();
        });

        return true;
    }

    test_receiver::status test_receiver::handle_do_run_shm(std::string start_breakpoint, std::string end_breakpoint, int shm_id, unsigned int offset)
    {
        log_info_message("TEST %s, %s", start_breakpoint.c_str(), end_breakpoint.c_str());
        log_info_message("Loading MMIO data from shared memory %d.", shm_id);

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

        test_receiver::status return_status = this->handle_do_run(start_breakpoint, end_breakpoint, mmio_data+offset, data_length);

        // Detach the shared memory
        if (shmdt(mmio_data) == -1) {
            LOG_ERROR("Failed to detach shared memory: %s", strerror(errno));
            // Continue to return the read data even if detaching fails
        }

        return return_status;
    }

    test_receiver::status test_receiver::handle_get_code_coverage_shm(int shm_id, unsigned int offset)
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

    void test_receiver::log_info_message(const char* fmt, ...){
        //To be overwritten of message should be logged.    
    }

    void test_receiver::log_error_message(const char* fmt, ...){
        //To be overwritten of message should be logged.    
    }

    void test_receiver::continue_to_next_event(){
        // Let's greenlight the other threads, we're ready to process
        sem_post(&m_empty_slots);
    }

    void test_receiver::wait_for_events_processes(){
        // Wait for all previous events were processes.
        sem_wait(&m_empty_slots);
    }

    void test_receiver::notify_event(){
        //Notify new event.
        sem_post(&m_full_slots);
    }

    void test_receiver::wait_for_event(){
        //Wait until next suspending.
        sem_wait(&m_full_slots);
    }

    bool test_receiver::is_event_queue_empty(){
        return m_event_queue.empty();
    }

    void test_receiver::add_event_to_queue(test_receiver::status event){
        m_event_queue.push_back(event);
    }

    test_receiver::status test_receiver::get_and_remove_first_event(){
        status last_event = m_event_queue.front();
        m_event_queue.pop_front();

        return last_event;
    }

    void test_receiver::reset_code_coverage(){
        // Writes all zeros to the basic block tracing array.
        memset(m_bb_array, 0, MAP_SIZE*sizeof(mwr::u8));
    }

    string test_receiver::get_code_coverage(){
        // Copying the bb tracke map to a string.
        std::vector<mwr::u8> v(m_bb_array, m_bb_array + sizeof m_bb_array / sizeof m_bb_array[0]);
        std::string s(v.begin(), v.end());
        return s;
    }

    void test_receiver::set_block(mwr::u64 pc){
        //Writing to the basic block traching map. 
        mwr::u64 curr_bb_loc = (pc >> 4) ^ (pc << 8);
        curr_bb_loc &= MAP_SIZE - 1;

        m_bb_array[curr_bb_loc ^ m_prev_bb_loc]++;
        m_prev_bb_loc = curr_bb_loc >> 1;
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

            case test_interface::GET_CODE_COVERAGE_SHM:
            {
                int shm_id = ((int)(unsigned char)req->data[0]) | ((int)(unsigned char)req->data[1] << 8) | ((int)(unsigned char)req->data[2] << 16) | ((int)(unsigned char)req->data[3] << 24);
                unsigned int offset = ((int)(unsigned char)req->data[4]) | ((int)(unsigned char)req->data[5] << 8) | ((int)(unsigned char)req->data[6] << 16) | ((int)(unsigned char)req->data[7] << 24);

                res->data = (char*)malloc(1);
                res->data[0] = handle_get_code_coverage_shm(shm_id, offset);
                res->data_length = 1;

                break;
            }

            case test_interface::WRITE_MMIO_WRITE_QUEUE:
            {
                //TODO!
            }

            default:
            {
                LOG_INFO("Command %d not found!", req->cmd);
                break;
            }

        }
    }

};