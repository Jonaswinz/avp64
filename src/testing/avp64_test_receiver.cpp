#include "testing/avp64_test_receiver.h"
#include "test_interface.h"

using namespace vcml::debugging;

namespace testing{

    void avp64_test_receiver::log_info_message(const char* fmt, ...){
        char buffer[1024];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);
        vcml::log_info("TEST_INTERFACE: %s", buffer);
    }

    void avp64_test_receiver::log_error_message(const char* fmt, ...){
        char buffer[1024];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);
        vcml::log_error("TEST_INTERFACE: %s", buffer);
    }

    avp64_test_receiver::avp64_test_receiver(const string& name, probe& get_probe, testing::MMIO_access& mmio_access, Can_injector& can_injector):
        test_receiver(),
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
        m_pipe_response_option("--test-receiver-pipe-response", "File descriptor of the pipe where responses are send to. Required for interface 1.") {}

    avp64_test_receiver::~avp64_test_receiver(){}

    void avp64_test_receiver::parse_args(int argc, const char* const* argv){
        m_enabled_option.parse(argc, argv);
        m_communication_option.parse(argc, argv);
        m_mq_request_option.parse(argc, argv);
        m_mq_response_option.parse(argc, argv);
        m_pipe_request_option.parse(argc, argv);
        m_pipe_response_option.parse(argc, argv);
    }

    void avp64_test_receiver::run(){

        // Do not start the test receiver if the option --enable-test-receiver is not set.
        if(!m_enabled_option.has_value() || !m_enabled_option.value()) return;

        // Log it as error so its still visible when only errors are logged.
        log_error_message("Test receiver enabled!");

        // Suspend the simulation right at the beginning
        m_is_sim_suspended = true;
        suspend();

        // Initialize the interface with was selected via the options.
        test_interface* interface;
        test_interface::interface selected_interface = test_interface::MQ;

        if(m_communication_option.has_value()){
            try{
                selected_interface = (test_interface::interface)std::stoi(m_communication_option.value());
            }catch(std::exception &e){
                log_error_message("Selected interface (--test-receiver-interface) is not valid number.");
                exit(1);
            }

            if(selected_interface >= test_interface::INTERFACE_COUNT){
                log_error_message("Selected interface (--test-receiver-interface) is invalid. Possible selection 0-%d.", test_interface::INTERFACE_COUNT-1); 
                exit(1);
            }

        }
        
        if(selected_interface == test_interface::MQ){

            if(!m_mq_request_option.has_value() || !m_mq_response_option.has_value()){
                log_error_message("In order to use MQ for communication --test-receiver-mq-request and --test-receiver-mq-response must be set!"); 
                exit(1);
            }

            //m_interface = new mq_test_interface("/avp64-test-receiver", "/avp64-test-sender");
            interface = new mq_test_interface(this, m_mq_request_option.value(), m_mq_response_option.value());

            log_info_message("Interface MQ selected for communication with fd %s and %s.", m_mq_request_option.value().c_str(), m_mq_response_option.value().c_str());  
        }else if(selected_interface == test_interface::PIPE){

            if(!m_pipe_request_option.has_value() || !m_pipe_response_option.has_value()){
                log_error_message("In order to use pipes for communication --test-receiver-pipe-request and --test-receiver-pipe-response must be set!"); 
                exit(1);
            }

            int pipe_request = -1;
            int pipe_response = -1;
            
            try{
                pipe_request = std::stoi(m_pipe_request_option.value());
                pipe_response = std::stoi(m_pipe_response_option.value());
            }catch(std::exception &e){
                log_error_message("specified pipes (--test-receiver-pipe-request or --test-receiver-pipe-response) are not valid numbers.");
                exit(1);
            }

            interface = new pipe_test_interface(this, pipe_request, pipe_response);   
            log_info_message("Interface pipes selected for communication with fd %d and %d.", pipe_request, pipe_response);  
        }

        if(!interface->start()){
            log_error_message("Error starting communication interface!"); 
            exit(1);
        }
        

        // Start the testing interface.
        start(interface);

        // Start the receiving loop as an independent thread.
        start_receiver_in_thread();

    }

    test_receiver::status avp64_test_receiver::handle_continue(){
        
        // Sends greelight to the other threads, so the execution can be continued
        continue_to_next_event();

        // If the buffer is not empty we use this handle_continue() to notify the client on previous events
        // So the simulation will only be resumed of the event queue is empty / handeled.
        // (every handle_continue removes one entry of the event queue).
        if(m_is_sim_suspended && is_event_queue_empty()){
            m_is_sim_suspended = false;
            resume();
        }

        // Run the simulation until an event (MMIO access, breakpoint hit ...)
        wait_for_event();

        // Sending the reason of the suspending (first element of the event queue)
        status last_event = get_and_remove_first_event();

        log_info_message("Continued to event: %d", last_event);

        return last_event;
    }

    test_receiver::status avp64_test_receiver::handle_kill(){
        log_info_message("Killing.");
        //TODO do immediately (gracefully option ?)
        m_kill_server = true;
        return STATUS_OK;
    }

    bool avp64_test_receiver::find_symbol_address(vcml::u64* addr, string name, bool set_breakpoint){

        // Searches all targets for a address by the symbole name
        for (auto* target : target::all()){
            const symbol* sym_ptr = target->symbols().find_symbol(name);
            if(sym_ptr){
                
                // Sets a breakpoint to this address if set_breakpoint is set.
                if(set_breakpoint) target->insert_breakpoint(sym_ptr->virt_addr(), this);
                *addr = sym_ptr->virt_addr();
                return true;
            }
        }

        return false;
    }

    std::vector<avp64_test_receiver::breakpoint>::iterator avp64_test_receiver::find_breakpoint(string name){
        auto it = std::find_if(m_active_breakpoints.begin(), m_active_breakpoints.end(), 
                                [&sn = name] (const breakpoint& bp)-> bool { return sn == bp.name;});
        return it;
    }

    std::vector<avp64_test_receiver::breakpoint>::iterator avp64_test_receiver::find_breakpoint(mwr::u64 addr){
        auto it = std::find_if(m_active_breakpoints.begin(), m_active_breakpoints.end(), 
                                [&sa = addr] (const breakpoint& bp)-> bool { return sa == bp.addr;});
        return it;
    }

    test_receiver::status avp64_test_receiver::handle_set_breakpoint(string &sym_name, int offset) {

        // Sets breakpoint by the symbole name and an offset.
        for (auto* target : target::all()) {

            auto it = find_breakpoint(sym_name);

            // If the breakpoint is not already set
            if(it == m_active_breakpoints.end()){

                const symbol* sym_ptr = target->symbols().find_symbol(sym_name); //get the symbol of the eg main from the symbols' list
                mwr::u64 sym_addr;

                if(sym_ptr)
                    sym_addr = sym_ptr->virt_addr() + offset;
                else 
                    return ERROR;

                if(sym_addr){
                    if(target->insert_breakpoint(sym_addr, this)){ 
                        m_active_breakpoints.push_back({sym_ptr, sym_name, sym_addr});
                        log_info_message("Breakpoint set to %s with offset %d.", sym_name.c_str(), offset);

                        return STATUS_OK;
                    } else
                        log_error_message("Failed to insert the breakpoint");
                } else
                log_error_message("Failed to retrieve the symbol's virtual address!");
            }
        }

        return STATUS_OK;
    }

    test_receiver::status avp64_test_receiver::handle_remove_breakpoint(string &sym_name){
        
        auto it = find_breakpoint(sym_name);

        // If the breakpoint was found
        if(it != m_active_breakpoints.end()){
            remove_breakpoint((*it).addr, it - m_active_breakpoints.begin());

            return STATUS_OK;
        } else
            log_error_message("Breakpoint was not set!");
        
        return ERROR;
    }

    void avp64_test_receiver::remove_breakpoint(mwr::u64 addr, int vector_idx)
    {
        for (auto* target : target::all()){
            target->remove_breakpoint(addr,this);
        }

        m_active_breakpoints.erase(m_active_breakpoints.begin() + vector_idx);
        log_info_message("Breakpoint removed.");
    }

    test_receiver::status avp64_test_receiver::handle_set_mmio_tracking(){
        // Enabling MMIO tracking.
        m_mmio_access->track_mmio_access = true;
        log_info_message("MMIO tracking enabled.");
        return STATUS_OK;
    }

    test_receiver::status avp64_test_receiver::handle_disable_mmio_tracking(){
        // Disabling MMIO tracking.
        m_mmio_access->track_mmio_access = false;
        log_info_message("MMIO tracking disabled.");
        return STATUS_OK;
    }

    test_receiver::status avp64_test_receiver::handle_set_code_coverage(){
        // Enabling basic block tracking for all targets.
        for (auto* target : target::all())
            target->trace_basic_blocks(this);
        log_info_message("Code coverage enabled.");
        return STATUS_OK;
    }

    test_receiver::status avp64_test_receiver::handle_reset_code_coverage(){
        reset_code_coverage();
        return STATUS_OK;
    }

    test_receiver::status avp64_test_receiver::handle_disable_code_coverage(){
        // Disabling basic block tracking for all targets.
        for (auto* target : target::all())
            target->untrace_basic_blocks(this);
        log_info_message("Code coverage disabled.");
        return STATUS_OK;
    }

    std::string avp64_test_receiver::handle_get_code_coverage()
    {
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
        
        return get_code_coverage();
    }

    void avp64_test_receiver::notify_basic_block(target& tgt, mwr::u64 pc, size_t blksz, size_t icount)
    {
        set_block(pc);
    }

    char avp64_test_receiver::handle_get_exit_status()
    {   
        log_info_message("Getting return code of %d.", m_ret_value);
        return m_ret_value;
    }

    test_receiver::status avp64_test_receiver::handle_do_run(std::string start_breakpoint, std::string end_breakpoint, char* mmio_data, size_t mmio_data_length)
    {   
        // Executing one run from a start breakpoint to an end breakpoint with a fixed MMIO read data

        log_info_message("Start breakpoint %s, end %s", start_breakpoint.c_str(), end_breakpoint.c_str());

        // Printing the mmio read data, but only when its zero terminated.
        if(mmio_data[mmio_data_length-1] == '\0'){
            log_info_message("Loaded test case: %s.", mmio_data);
        }else{
            log_info_message("Could not print test case, because there is not a termination character.");
        }

        // Setting the read queue to our mmio data, so its used without suspending MMIO events.
        m_probe->set_read_queue(mmio_data, mmio_data_length);

        // Setting end breakpoint. It is asumed here, that the simulation is currently at the start breakpoint or similar (somewhere before the target MMIO access).
        // The end breakpoint is set with run_until, which means that every event is ignored that is not the end breakpoint hit. This makes the execution much faster. The MMIO read queue will still be used. But if the target program requests more data than there is in the read queue this MMIO read event will also be ignored. If then the target program never hits the end breakpoint a infinite loop is then created here!
        log_info_message("Setting end breakpoint.");

        if(!find_symbol_address(&m_run_until_breakpoint_addr, end_breakpoint, true)){
            log_error_message("End breakpoint was not found!");

            // Resetting and returning error
            m_probe->reset_read_queue();
            return ERROR;
        }
        m_run_until_breakpoint = true;

        // Set m_exit_breakpoint_address, so the exit code is still recorded.
        m_exit_breakpoint_address = m_run_until_breakpoint_addr;

        // Starts the run and the the next event should be the end breakpoint (run_until).
        status last_status = handle_continue();

        //TODO add timeout!
        
        //If there was a different event, then an error occured.
        if(last_status != BREAKPOINT_HIT){
            log_error_message("Stopped not at the expected breakpoint!");

            if(last_status == VP_END){
                log_error_message("VP finished before the end breakpoint!");
            }

            // Resetting and returning error
            m_run_until_breakpoint = false;
            m_probe->reset_read_queue();
            return ERROR;
        }

        // Only run until the start breakpoint, when a start breakpoint was given. This is for example required in the persistent mode, where the target restarts itself.
        if(end_breakpoint != ""){
            // Setting the start breakpoint, which is catched, when the target program loops back to the beginning. This is important for the persistent mode.
            log_info_message("Setting start breakpoint.");

            if(find_symbol_address(&m_run_until_breakpoint_addr, start_breakpoint, true)){
                log_error_message("Start breakpoint was not found!");
                return ERROR;

                // Resetting and returning error
                m_run_until_breakpoint = false;
                m_probe->reset_read_queue();
            }
            m_run_until_breakpoint = true;

            // Continues the executio to the start breakpoint where the next run can be started.
            log_info_message("Continuing until start breakpoint.");
            last_status = handle_continue();

            if(last_status != BREAKPOINT_HIT){
                log_error_message("Stopped not at the expected breakpoint!");

                if(last_status == VP_END){
                    log_error_message("VP finished before the start breakpoint!");
                }

                // Resetting and returning error
                m_run_until_breakpoint = false;
                m_probe->reset_read_queue();
                return ERROR;
            }
        }

        // Resetting run_until and the MMIO read queue.
        m_run_until_breakpoint = false;
        m_probe->reset_read_queue();

        return STATUS_OK;
    }

    void avp64_test_receiver::notify_breakpoint_hit(const vcml::debugging::breakpoint& bp){

        // Check if the breakpoint was hit, where we are interested in the return code.
        if(bp.address() == m_exit_breakpoint_address){
            // Read the register which contains the return code (this depends on the core used!).
            m_ret_value = read_reg_value("x0");
            log_info_message("Exit return value: %d.", m_ret_value);
        }

        // If we are currently in run_until mode ignore all breakpoint hits that are not the target one.
        if(m_run_until_breakpoint && bp.address() != m_run_until_breakpoint_addr){
            return;
        }

        wait_for_events_processes();

        // Suspend the simulation if not already TODO: maybe do it differently, so the simulation does not run between this and the line before!
        if(!m_is_sim_suspended){
            m_is_sim_suspended = true;
            suspend();
        }

        // Add to event qeueu.
        add_event_to_queue(status::BREAKPOINT_HIT);

        notify_event();

        // If the breakpoint was added to the active breakpoint lists remove it.
        mwr::u64 addr = bp.address();
        auto it = find_breakpoint(addr);

        // If we run into the exit breakpoint read the register with the result (0 success, 1 fault)
        if(it != m_active_breakpoints.end()){
            log_info_message("Breakpoit %s hit.", it->name.c_str());
            
            if(!it->name.compare("exit")){
                m_ret_value = read_reg_value("x0");
                log_info_message("Exit return value: %d.", m_ret_value);
            }
            
            remove_breakpoint(bp.address(), it-m_active_breakpoints.begin());
        }
    }

    char avp64_test_receiver::read_reg_value(string reg_name)
    {
        int read_val;

        for (auto* target : target::all()){
            const cpureg *reg = target->find_cpureg(reg_name);
            reg->read(&read_val, reg->size);
        }

        //TODO need to change to a larger than char
        return (char)read_val;
    }

    void avp64_test_receiver::notify_vp_finished()
    {
        wait_for_events_processes();
        log_info_message("VP finished.");
        add_event_to_queue(status::VP_END);
        notify_event();

        log_info_message("Waiting for kill command.");

        //Bussy waiting for getting killed!
        //TODO differently ?
        while(!m_kill_server);
    }

    void avp64_test_receiver::on_mmio_access(vcml::tlm_generic_payload& tx)
    {
        if(!m_run_until_breakpoint){

            log_info_message("MMIO access event.");

            tlm::tlm_command cmd = tx.get_command();
            unsigned char* ptr = tx.get_data_ptr();
            unsigned int length = tx.get_data_length(); // this should be 1 byte
            uint64_t mmio_addr = tx.get_address();

            wait_for_events_processes();

            if(m_mmio_access->track_mmio_access) //Let's check the client didn't de-activate the tracking while we were waiting
            {
                if(cmd == tlm::TLM_READ_COMMAND){
                    add_event_to_queue(status::MMIO_READ);
                    m_mmio_access->read_data.length = length;
                }else
                { 
                    add_event_to_queue(status::MMIO_WRITE);

                    auto mmio_val = std::make_unique<unsigned char[]>(length);

                    for(uint32_t i=0; i<length; i++)
                        mmio_val[i]= *(ptr+i);

                    m_mmio_access->write_data_buffer.push(MMIO_access::data{std::move(mmio_val), length, mmio_addr}); 
                }
                if(!m_is_sim_suspended){
                    m_is_sim_suspended = true;
                    suspend();
                }

                notify_event();

                if(cmd == tlm::TLM_READ_COMMAND)
                {
                    std::unique_lock lk(m_mmio_access->mmio_data_mtx);
                    m_mmio_access->mmio_data_cv.wait(lk, [this]{ return m_mmio_access->read_data.ready; });

                    m_mmio_access->read_data.ready = false;
                    
                    memcpy(ptr, m_mmio_access->read_data.value.get(), length);

                    lk.unlock();
                }
            }
            else{
                // if track_mmio_access is false, then release the lock
                continue_to_next_event();
            } 
                

        }else{
            log_info_message("MMIO access event skipped, because of run until breakpoint!");
        }
        
        tx.set_response_status(tlm::TLM_OK_RESPONSE);
        // If when a write comes we want to immediately block the simulation this should be enabled
        //while(is_sim_suspended);
    }

    test_receiver::status avp64_test_receiver::handle_set_mmio_value(char* value, size_t length)
    {
        log_info_message("Writing MMIO value of length %d.", (int)length);

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

    test_receiver::status avp64_test_receiver::handle_write_mmio_write_queue(char* value, size_t length){
        //TODO
        return ERROR;
    }

};