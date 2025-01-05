#include "fuzzing/test_receiver.h"

using namespace vcml::debugging;

namespace fuzzing{

    TestReceiver::TestReceiver(const string& name, fuzzing::MMIO_access& mmio_access, Can_injector& can_injector):suspender(name),subscriber(),mmio_access_ptr(&mmio_access),
can_injector_ptr(&can_injector)
    {
        sem_init(&emptySlots, 0, 0); 
        sem_init(&fullSlots, 0, 0);

        run();
        is_sim_suspended = true;
        suspend();
    }

    TestReceiver::~TestReceiver(){
        sem_destroy(&emptySlots);
        sem_destroy(&fullSlots);
    }

    void clearMessageQueue(const char* queueName) {
        mqd_t mqd = mq_open(queueName, O_RDONLY | O_NONBLOCK);
        if (mqd == -1) {
            return;
        }

        struct mq_attr attr;
        mq_getattr(mqd, &attr);
        char* buffer = new char[attr.mq_msgsize];

        while (true) {
            ssize_t bytes_read = mq_receive(mqd, buffer, attr.mq_msgsize, NULL);
            if (bytes_read == -1) {
                if (errno == EAGAIN) {
                    LOG_INFO("Message queue is now empty.");
                    break;
                }
            }
        }

        delete[] buffer;
        mq_close(mqd);
    }

    void TestReceiver::run(){

        attr.mq_flags = 0;
        attr.mq_maxmsg = 10;
        attr.mq_msgsize = REQUEST_LENGTH;
        attr.mq_curmsgs = 0;

        clearMessageQueue("/avp64-test-receiver");
        clearMessageQueue("/avp64-test-sender");

        if ((mqt_requests = mq_open("/avp64-test-receiver", O_RDONLY | O_CREAT, 0660, &attr)) == -1) {
            LOG_ERROR("Error opening request message queue.");
            exit(1);
        }

        if ((mqt_responses = mq_open("/avp64-test-sender", O_WRONLY | O_CREAT, 0644, &attr)) == -1) {
            LOG_ERROR("Error opening response message queue.");
            exit(1);
        }

        string readySignal = "ready";
        mq_send(mqt_responses, readySignal.c_str(), readySignal.size(), 0);

        LOG_INFO("Message queues ready, waiting for requests.");

        interface_thread = std::thread([this] {
            this->messageReceiver();
        });

    }

    void TestReceiver::messageReceiver() {

        while (true) {
            // Clear buffer
            memset(buffer, 0, sizeof(buffer));

            // Receive message
            bytes_read = mq_receive(mqt_requests, buffer, REQUEST_LENGTH, NULL);
            if (bytes_read >= 1) {

                //Copy received data to a valid request
                Request request = Request();
                request.dataLength = bytes_read;
                request.command = (Command)buffer[0];
                if(bytes_read > 1) std::memcpy(&(request.data), buffer+1, bytes_read-1);

                LOG_INFO("Received command: %d", (uint8_t)request.command);

                Response response = Response();

                if(request.command == GET_CODE_COVERAGE){

                    std::string code_coverage = handleGetCodeCoverage();
                    size_t sendIndex = 0;
                    size_t fullLength = (size_t)code_coverage.size();
                    
                    //Sending head
                    Response headResponse = Response();
                    memcpy(headResponse.data, &fullLength, sizeof(fullLength));
                    headResponse.dataLength = sizeof(size_t);
                    mq_send(mqt_responses, headResponse.data, headResponse.dataLength, 0);

                    //Sending code coverage in chunks
                    while(sendIndex < fullLength){
                        size_t chunkLength = std::min((size_t)code_coverage.size()-sendIndex,(size_t)RESPONSE_LENGTH);
                        mq_send(mqt_responses, code_coverage.c_str()+sendIndex, chunkLength, 0);
                        sendIndex += chunkLength;
                    }

                }else{

                    //Handling request
                    handleCommand(&request, &response);

                    if(mq_send(mqt_responses, response.data, response.dataLength, 0) == -1){
                        LOG_ERROR("Error sending response data: %s", strerror(errno));
                    }

                }

                

            } else {
                LOG_ERROR("Error receiving request data: %s (bytes_read: %d)", strerror(errno), (int)bytes_read);
            }
        }
    }

    void TestReceiver::handleCommand(Request* request, Response* response){

        switch(request->command){

            case CONTINUE:
            {
                response->data[0] = handleContinue();
                response->dataLength = 1;
                break;
            }

            case KILL:
            {
                response->data[0] = handleKill();
                response->dataLength = 1;
                break;
            }

            case SET_BREAKPOINT:
            {
                uint8_t offset = request->data[0];
                string symbol_name(request->data + 1, request->dataLength-1);

                response->data[0] = handleSetBreakpoint(symbol_name.c_str(), offset);
                response->dataLength = 1;
                break;
            }

            case REMOVE_BREAKPOINT:
            {
                string symbol_name(request->data, request->dataLength);

                response->data[0] = handleRemoveBreakpoint(symbol_name.c_str());
                response->dataLength = 1;
                break;
            }

            case SET_MMIO_TRACKING:
            {
                response->data[0] = handleSetMMIOTracking();
                response->dataLength = 1;
                break;
            }

            case DISABLE_MMIO_TRACKING:
            {
                response->data[0] = handleDisableMMIOTracking();
                response->dataLength = 1;
                break;
            }

            case SET_MMIO_VALUE:
            {   
                response->data[0] = handleSetMMIOValue(&request->data[1], request->data[0]);
                response->dataLength = 1;
                break;
            }

            case SET_CODE_COVERAGE:
            {
                response->data[0] = handleSetCodeCoverage();
                response->dataLength = 1;
                break;
            }

            case RESET_CODE_COVERAGE:
            {
                response->data[0] = handleResetCodeCoverage();
                response->dataLength = 1;
                break;
            }

            case REMOVE_CODE_COVERAGE:
            {
                response->data[0] = handleDisableCodeCoverage();
                response->dataLength = 1;
                break;
            }

            case GET_EXIT_STATUS:
            {   
                response->data[0] = handleGetExitStatus();
                response->dataLength = 1;
                break;
            }

            case DO_RUN:
            {

                // Data:
                // Length start breakpoint +
                // Start breakpoint name +
                // Length end breakpoint +
                // End breakpoint name +
                // Read data length
                // Read data

                int start_breakpoint_length = request->data[0];
                string start_breakpoint(&request->data[1], start_breakpoint_length);

                int end_breakpoint_length = request->data[start_breakpoint_length+1];
                string end_breakpoint(&request->data[start_breakpoint_length+2], end_breakpoint_length);

                int read_data_length = request->data[start_breakpoint_length+end_breakpoint_length+2];

                response->data[0] = handleDoRun(start_breakpoint, end_breakpoint, &request->data[start_breakpoint_length+end_breakpoint_length+3], read_data_length);
                response->dataLength = 1;
                break;
            }

            case WRITE_CODE_COVERAGE:
            {
                int shm_id = ((int)(unsigned char)request->data[0]) | ((int)(unsigned char)request->data[1] << 8) | ((int)(unsigned char)request->data[2] << 16) | ((int)(unsigned char)request->data[3] << 24);

                LOG_INFO("%02X, %02X, %02X, %02X", request->data[0], request->data[1], request->data[2], request->data[3]);

                response->data[0] = handleWriteCodeCoverage(shm_id);
                response->dataLength = 1;

                break;
            }

            default:
            {
                LOG_INFO("Command not found!");
                break;
            }

        }
    }

    TestReceiver::Status TestReceiver::handleContinue(){
        // Let's greenlight the other threads, we're ready to process
        sem_post(&emptySlots);

        // If the buffer is not empty we use this handle_continue()
        // execution to notify the client on previous events
        if(is_sim_suspended && exitID_buffer.empty()){
            is_sim_suspended = false;
            resume();
        }

        //Wait until next suspending.
        sem_wait(&fullSlots);

        //Sending the reason of the suspending.
        Status exitID = exitID_buffer.front();
        exitID_buffer.pop_front();

        LOG_INFO("Event: %d", exitID);

        return exitID;
    }

    TestReceiver::Status TestReceiver::handleKill(){
        LOG_INFO("Killing.");
        kill_server = true;
        return STATUS_OK;
    }

    std::vector<TestReceiver::Breakpoint>::iterator TestReceiver::find_breakpoint(string name){
        auto it = std::find_if(active_breakpoints.begin(), active_breakpoints.end(), 
                                [&sn = name] (const Breakpoint& bp)-> bool { return sn == bp.name;});
        return it;
    }

    std::vector<TestReceiver::Breakpoint>::iterator TestReceiver::find_breakpoint(mwr::u64 addr){
        auto it = std::find_if(active_breakpoints.begin(), active_breakpoints.end(), 
                                [&sa = addr] (const Breakpoint& bp)-> bool { return sa == bp.addr;});
        return it;
    }

    TestReceiver::Status TestReceiver::handleSetBreakpoint(string sym_name, int offset) {

        for (auto* target : target::all()) {

            auto it = find_breakpoint(sym_name);

            //if the breakpoint is not already set
            if(it == active_breakpoints.end()){

                const symbol* sym_ptr = target->symbols().find_symbol(sym_name); //get the symbol of the eg main from the symbols' list
                mwr::u64 sym_addr;

                if(sym_ptr)
                    sym_addr = sym_ptr->virt_addr() + offset; // -1 is a workaround for elf reader quirks
                else 
                    return ERROR;

                if(sym_addr){
                    if(target->insert_breakpoint(sym_addr, this)){ 
                        active_breakpoints.push_back({sym_ptr, sym_name, sym_addr});
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
    TestReceiver::Status TestReceiver::handleRemoveBreakpoint(string sym_name){
        
        auto it = find_breakpoint(sym_name);

        if(it != active_breakpoints.end()){
            removeBreakpoint((*it).addr, it - active_breakpoints.begin());

            return STATUS_OK;
        } else
            LOG_ERROR("Breakpoint was not set!");
        
        return ERROR;
    }

    void TestReceiver::removeBreakpoint(mwr::u64 addr, int vector_idx)
    {
        for (auto* target : target::all()){
            target->remove_breakpoint(addr,this);
        }

        active_breakpoints.erase(active_breakpoints.begin() + vector_idx);
        LOG_INFO("Breakpoint removed.");
    }

    TestReceiver::Status TestReceiver::handleSetMMIOTracking(){
        mmio_access_ptr->track_mmio_access = true;
        LOG_INFO("MMIO tracking enabled.");
        return STATUS_OK;
    }

    TestReceiver::Status TestReceiver::handleDisableMMIOTracking(){
        mmio_access_ptr->track_mmio_access = false;
        LOG_INFO("MMIO tracking disabled.");
        return STATUS_OK;
    }

    TestReceiver::Status TestReceiver::handleSetCodeCoverage()
    {
        for (auto* target : target::all())
            target->trace_basic_blocks(this);
        LOG_INFO("Code coverage enabled.");
        return STATUS_OK;
    }

    TestReceiver::Status TestReceiver::handleResetCodeCoverage()
    {
        memset(bb_array, 0, MAP_SIZE*sizeof(mwr::u8));
        return STATUS_OK;
    }

    TestReceiver::Status TestReceiver::handleDisableCodeCoverage()
    {
        for (auto* target : target::all())
            target->untrace_basic_blocks(this);
        LOG_INFO("Code coverage disabled.");
        return STATUS_OK;
    }

    std::string TestReceiver::handleGetCodeCoverage()
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

        std::vector<mwr::u8> v(bb_array, bb_array + sizeof bb_array / sizeof bb_array[0]);
        std::string s(v.begin(), v.end());
        return s;
    }

    void TestReceiver::notify_basic_block(target& tgt, mwr::u64 pc, size_t blksz, size_t icount)
    {
        //LOG_INFO("Basic block notification.");
        
        mwr::u64 curr_bb_loc = (pc >> 4) ^ (pc << 8);
        curr_bb_loc &= MAP_SIZE - 1;

        bb_array[curr_bb_loc ^ prev_bb_loc]++;
        prev_bb_loc = curr_bb_loc >> 1;
    }

    char TestReceiver::handleGetExitStatus()
    {   
        LOG_INFO("Getting return code of %d.", ret_value);
        return ret_value;
    }

    TestReceiver::Status TestReceiver::handleDoRun(std::string start_breakpoint, std::string end_breakpoint, char* MMIO_data, size_t data_length)
    {   
        LOG_INFO("Start breakpoint %s, end %s, data length %d", start_breakpoint.c_str(), end_breakpoint.c_str(), (int)data_length);
        
        //LOG_INFO("Setting MMIO data");
        //handleSetMMIOValue(data, data_length);

        LOG_INFO("Setting end breakpoint.");
        handleSetBreakpoint(end_breakpoint, 0);

        size_t MMIO_data_index = 0;

        Status lastStatus = handleContinue();

        while(true){

            if(lastStatus == VP_END){
                LOG_INFO("Run loop: VP_END.");
                break;
            }else if(lastStatus == MMIO_READ){
                LOG_INFO("Run loop: MMIO_READ.");

                if(MMIO_data_index < data_length+1){
                    
                    LOG_INFO("Run loop: Setting MMIO value %c", MMIO_data[MMIO_data_index]);

                    lastStatus = handleSetMMIOValue(&MMIO_data[MMIO_data_index], 1);
                    MMIO_data_index ++;

                }else{
                    LOG_INFO("Run loop: ERROR! More data requested!");
                    lastStatus = handleSetMMIOValue(0, 1);
                }

            }else if(lastStatus == BREAKPOINT_HIT){
                LOG_INFO("Run loop: Breakpoint hit.");
                break;
            }else{
                LOG_INFO("Run loop: Other");
                lastStatus = handleContinue();
            }
        }

        //TODO hangle: VP_END

        LOG_INFO("Setting start breakpoint.");
        handleSetBreakpoint(start_breakpoint, 0);

        LOG_INFO("Continuing until start breakpoint.");

        //TODO: VP_END !?
        while(true){
            lastStatus = handleContinue();
            if(lastStatus == BREAKPOINT_HIT){
                break;
            }
        }

        return STATUS_OK;
    }

    void TestReceiver::notify_breakpoint_hit(const breakpoint& bp){
        sem_wait(&emptySlots);

        exitID_buffer.push_back(Status::BREAKPOINT_HIT);
        if(!is_sim_suspended){
            is_sim_suspended = true;
            suspend();
        }
        sem_post(&fullSlots);

        mwr::u64 addr = bp.address();
        auto it = find_breakpoint(addr);

        // If we run into the exit breakpoint read the register with the result (0 success, 1 fault)
        if(it != active_breakpoints.end()){
            LOG_INFO("Breakpoit %s hit.", it->name.c_str());

            int str_eq = active_breakpoints[it - active_breakpoints.begin()].name.compare("exit");
            if(!str_eq){
                ret_value = readRegValue("x0");
                LOG_INFO("Exit return value: %d.", ret_value);
            }
        }
        
        removeBreakpoint(bp.address(), it-active_breakpoints.begin());
    }

    char TestReceiver::readRegValue(string reg_name)
    {
        int read_val;

        for (auto* target : target::all()){
            const cpureg *reg = target->find_cpureg(reg_name);
            reg->read(&read_val, reg->size);
        }

        //TODO need to change!
        return (char)read_val;
    }

    #pragma GCC push_options
    #pragma GCC optimize("O0")
    void TestReceiver::notify_vp_finished()
    {
        LOG_INFO("VP finished.");
        sem_wait(&emptySlots);
        exitID_buffer.push_back(Status::VP_END);
        sem_post(&fullSlots);

        LOG_INFO("Waiting for kill request.");
        while(!kill_server);
    }
    #pragma GCC pop_options

    void TestReceiver::on_mmio_access(vcml::tlm_generic_payload& tx)
    {
        LOG_INFO("MMIO access event.");

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

    TestReceiver::Status TestReceiver::handleSetMMIOValue(char* value, size_t length)
    {
        LOG_INFO("Writing MMIO value of length %d.", (int)length);

        std::unique_lock lk(mmio_access_ptr->mmio_data_mtx);
        
        mmio_access_ptr->read_data.length = length;

        auto uchar_arr =  std::make_unique<unsigned char[]>(length);
        for(size_t i=0; i<length; i++)
            uchar_arr[i] = value[i];

        mmio_access_ptr->read_data.value = std::move(uchar_arr);

        mmio_access_ptr->read_data.ready = true;
        lk.unlock();
        mmio_access_ptr->mmio_data_cv.notify_one();

        return STATUS_OK;
    }

    TestReceiver::Status TestReceiver::handleWriteCodeCoverage(int shm_id)
    {
        LOG_INFO("Writing Code Coverage to %d.", shm_id);

        // Attach the shared memory segment
        char* shm_addr = static_cast<char*>(shmat(shm_id, nullptr, 0));
        if (shm_addr == reinterpret_cast<char*>(-1)) {
            LOG_ERROR("Failed to attach shared memory: %s", strerror(errno));
            return ERROR;
        }

        // Write the data to the shared memory
        std::memcpy(shm_addr, bb_array, MAP_SIZE*sizeof(mwr::u8));

        // Detach the shared memory
        if (shmdt(shm_addr) == -1) {
            LOG_ERROR("Failed to detach shared memory: %s", strerror(errno));
            return ERROR;
        }

        return STATUS_OK;
    }

};