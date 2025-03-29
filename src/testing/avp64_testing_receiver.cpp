#include "testing/avp64_testing_receiver.h"
#include "testing_communication.h"

using namespace vcml::debugging;

namespace testing{

    avp64_testing_receiver::avp64_testing_receiver(const string& name, mmio_probe& get_probe, avp64::core* core):
        testing_receiver(),
        suspender(name),
        subscriber(),
        m_mmio_probe(&get_probe),
        target_core(core),
        m_enabled_option("--enable-test-receiver", "Enables the test-receiver to automatically run tests inside avp64."),
        m_communication_option("--test-receiver-interface", "Sets the interfacing method of the test receiver. 0: Message queues, 1: pipes."),
        m_mq_request_option("--test-receiver-mq-request", "File descriptor of the message queue where requests are read from. Required for interface 0."),
        m_mq_response_option("--test-receiver-mq-response", "File descriptor of the message queue where responses are send to. Required for interface 0."),
        m_pipe_request_option("--test-receiver-pipe-request", "File descriptor of the pipe where requests are read from. Required for interface 1."),
        m_pipe_response_option("--test-receiver-pipe-response", "File descriptor of the pipe where responses are send to. Required for interface 1.") {

            VCML_ERROR_ON(target_core == nullptr, "Target core is a nullptr!");
        }

    avp64_testing_receiver::~avp64_testing_receiver(){}

    void avp64_testing_receiver::parse_args(int argc, const char* const* argv){
        // Manually parse all start agruments.
        m_enabled_option.parse(argc, argv);
        m_communication_option.parse(argc, argv);
        m_mq_request_option.parse(argc, argv);
        m_mq_response_option.parse(argc, argv);
        m_pipe_request_option.parse(argc, argv);
        m_pipe_response_option.parse(argc, argv);
    }

    void avp64_testing_receiver::init(){

        // Do not start the test receiver if the option --enable-test-receiver is not set.
        if(!m_enabled_option.has_value() || !m_enabled_option.value()) return;

        // Log it as error so its still visible when only errors are logged.
        log_error_message("Test receiver enabled!");

        // Suspend the simulation right at the beginning
        m_is_sim_suspended = true;
        suspend();

        // Initialize the interface with was selected via the options.
        testing_communication* selected_communication;
        communication selected_interface = communication::MQ;

        // Parse selected communication interface.
        if(m_communication_option.has_value()){
            try{
                selected_interface = (communication)std::stoi(m_communication_option.value());
            }catch(std::exception &e){
                log_error_message("Selected interface (--test-receiver-interface) is not valid number.");
                shutdown();
            }

            if(selected_interface >= communication::COMMUNICATION_COUNT){
                log_error_message("Selected interface (--test-receiver-interface) is invalid. Possible selection 0-%d.", communication::COMMUNICATION_COUNT-1); 
                shutdown();
            }

        }
        
        // Init selected communication interface.
        if(selected_interface == communication::MQ){

            if(!m_mq_request_option.has_value() || !m_mq_response_option.has_value()){
                log_error_message("In order to use MQ for communication --test-receiver-mq-request and --test-receiver-mq-response must be set!"); 
                shutdown();
            }

            //m_interface = new mq_test_interface("/avp64-test-receiver", "/avp64-test-sender");
            selected_communication = new mq_testing_communication(this, m_mq_request_option.value(), m_mq_response_option.value());

            log_info_message("Interface MQ selected for communication with fd %s and %s.", m_mq_request_option.value().c_str(), m_mq_response_option.value().c_str());  
        
        }else if(selected_interface == communication::PIPE){

            if(!m_pipe_request_option.has_value() || !m_pipe_response_option.has_value()){
                log_error_message("In order to use pipes for communication --test-receiver-pipe-request and --test-receiver-pipe-response must be set!"); 
                shutdown();
            }

            int pipe_request = -1;
            int pipe_response = -1;
            
            try{
                pipe_request = std::stoi(m_pipe_request_option.value());
                pipe_response = std::stoi(m_pipe_response_option.value());
            }catch(std::exception &e){
                log_error_message("specified pipes (--test-receiver-pipe-request or --test-receiver-pipe-response) are not valid numbers.");
                shutdown();
            }

            selected_communication = new pipe_testing_communication(this, pipe_request, pipe_response);   
            log_info_message("Interface pipes selected for communication with fd %d and %d.", pipe_request, pipe_response);  
        }

        // Start selected communication interface.
        if(!selected_communication->start()){
            log_error_message("Error starting communication interface!"); 
            shutdown();
        }
        
        // Set the started communication interface to be used by the testing receiver.
        set_communication(selected_communication);

        // Start the receiving loop as an independent thread.
        start_receiver_in_thread();

    }

    void avp64_testing_receiver::log_info_message(const char* fmt, ...){
        char buffer[1024];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);
        // Uses vcml logging.
        vcml::log_info("TEST_INTERFACE: %s", buffer);
    }

    void avp64_testing_receiver::log_error_message(const char* fmt, ...){
        char buffer[1024];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);
        // Uses vcml logging.
        vcml::log_error("TEST_INTERFACE: %s", buffer);
    }

    void avp64_testing_receiver::notify_breakpoint_hit(const vcml::debugging::breakpoint& bp){

        log_info_message("Breakpoint event: %d!", (int)bp.address());

        // Check error symbol
        if(bp.address() == error_symbol_address){
            suspend_simulation();
            notify_event(event{ERROR_SYMBOL_HIT, nullptr, 0}); 
        }

        // Check if interrupt should be fired.
        target_core->check_interrupt(bp.address());

        // Check if the breakpoint was hit, where we are interested in the return code.
        if(m_ret_recording_enabled && bp.address() == m_ret_address){
            // Read the register which contains the return code (this depends on the core used!).
            if(read_reg_value(m_ret_value, m_ret_register)){
                log_info_message("Return value recorded: %d.", m_ret_value);
                m_ret_value_set = true;
            }else{
                log_error_message("Error during return value recording!");
                m_ret_value_set = false;
            }
        }

        // If we are currently in run_until mode ignore all breakpoint hits that are not the target one. With this the performance is improved, because the simulation is not suspended and the breakpoint vector is not searched.
        if(m_run_until_breakpoint && bp.address() != m_run_until_breakpoint_addr){
            return;
        }

        wait_for_events_processes();

        // Suspend the simulation if not already.
        suspend_simulation();

        // If run until mode is activated, trigger a BREAKPOINT_HIT without a symbol name. This is required for DO_RUN to work, because it also uses the continue function, but without a propertly set breakpoint.
        if(m_run_until_breakpoint){
            notify_event(event{BREAKPOINT_HIT, nullptr, 0});
            return;
        }

        //Synchronize access to the active breakpoint vector, because it may access by multiple threads (simulation and receiving loop).
        {
            std::lock_guard<std::mutex> lock(m_active_breakpoints_mutex);

            auto it = find_breakpoint(bp.address());

            // If we run into the exit breakpoint read the register with the result (0 success, 1 fault)
            if(it != m_active_breakpoints.end()){
                log_info_message("Breakpoit %s hit.", it->name.c_str());
                
                // Add to event qeueu and signal new event.
                notify_BREAKPOINT_HIT_event(it->name);
                
                remove_breakpoint(bp.address(), it-m_active_breakpoints.begin());
            }

        }
    }

    void avp64_testing_receiver::notify_basic_block(target& tgt, mwr::u64 pc, size_t blksz, size_t icount)
    {
        // Forward the block notification to the default testing receivers coverage tracking.
        set_block(pc);
    }

    void avp64_testing_receiver::on_mmio_access(tlm::tlm_command cmd, unsigned char* ptr, uint64_t mmio_addr, unsigned int length)
    {
        // This function will be called if MMIO tracking is enabled (and the mode is set) and a read or write was requested by the CPU for the set range.
        // This function will not be called, if there was a MMIO read and a suitable element in the read queue (managed by the mmio_probe).

        // Check if length can be casted to 32bit unsigned int (only supported by the communication).
        VCML_ERROR_ON(!testing::testing_communication::check_cast_to_uint32(length), "MMIO read length can not be casted to uint32. Tracking for longer reads is currently not supported!");

        if(cmd != tlm::TLM_READ_COMMAND && cmd != tlm::TLM_WRITE_COMMAND){
            log_info_message("Other MMIO event (not handeled).");
            return;
        }

        // If we are currently in run_until mode ignore all MMIO access events.
        if(!m_run_until_breakpoint){

            wait_for_events_processes();

            suspend_simulation();

            if(cmd == tlm::TLM_READ_COMMAND){

                log_info_message("MMIO read event.");

                // Add new MMIO_READ event and notify.
                notify_MMIO_READ_event(mmio_addr, (uint32_t)length);

            }else if(cmd == tlm::TLM_WRITE_COMMAND){ 

                log_info_message("MMIO write event.");
                
                //Add new event and notify.
                notify_MMIO_WRITE_event(mmio_addr, (uint32_t)length, (char *)ptr);
            }

            // Create a new mutex for this MMIO event.
            sem_t* new_mmio_event_mutex = new sem_t;
            sem_init(new_mmio_event_mutex, 0, 0);

            {
                // Synchronize access to the mmio event queue vector, because it may access by multiple threads (simulation and receiving loop).
                std::lock_guard<std::mutex> lock(m_mmio_event_queue_mutex);

                // Add the new MMIO event to the MMIO event queue.
                m_mmio_event_queue.push_back(mmio_event{new_mmio_event_mutex, cmd, ptr, mmio_addr, length});
            }

            // Wait for mutex (payload data to be set). This mutex will be release when the command SET_MMIO_DATA is executed.
            sem_wait(new_mmio_event_mutex);

            {
                // Synchronize access to the mmio event queue vector, because it may access by multiple threads (simulation and receiving loop).
                std::lock_guard<std::mutex> lock(m_mmio_event_queue_mutex);
                
                // Remove the event again.
                m_mmio_event_queue.erase(std::remove_if(m_mmio_event_queue.begin(), m_mmio_event_queue.end(),[new_mmio_event_mutex](const mmio_event& event) {
                    return event.mutex == new_mmio_event_mutex;  // Compare pointers
                    }),m_mmio_event_queue.end());
            }
            
            // Delete the mutex.
            sem_destroy(new_mmio_event_mutex);
            delete new_mmio_event_mutex;

        }else{
            log_info_message("MMIO event skipped, because of run until enabled!");
        }
    }

    void avp64_testing_receiver::notify_vp_finished()
    {
        wait_for_events_processes();

        log_info_message("VP finished.");

        notify_VP_END_event();

        log_info_message("Waiting for kill command.");

        //Bussy waiting for getting killed!
        while(!m_kill_server);
    }

    status avp64_testing_receiver::handle_continue(event &last_event){
        
        // Sends greelight to the other threads, so the execution can be continued
        continue_to_next_event();

        // If the buffer is not empty we use this handle_continue() to notify the client on previous events
        // So the simulation will only be resumed if the event queue is empty / handeled.
        // (every handle_continue removes one entry of the event queue).

        if(!is_event_queue_empty()){    
            // Sending the reason of the suspending (first element of the event queue)
            last_event = get_and_remove_first_event();

            log_info_message("Event queue not empty! First event: %d", last_event.event);
            return STATUS_OK;
        }
    
        {
            // Synchronize access to the mmio event queue vector, because it may access by multiple threads (simulation and receiving loop).
            std::lock_guard<std::mutex> lock(m_mmio_event_queue_mutex);
            if(!m_mmio_event_queue.empty()){
                log_info_message("Not all MMIO event are handeled. Cannot continue!");
                return STATUS_ERROR; 
            }
        }

        log_info_message("Event queue empty, continuing simulation.");

        // Resumte simulation
        resume_simulation();

        // Wait until the next event (MMIO access, breakpoint hit ...)
        wait_for_event();

        // Sending the reason of the suspending (first element of the event queue)
        last_event = get_and_remove_first_event();

        log_info_message("Continued to event: %d", last_event.event);

        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_kill(bool gracefully){
        log_info_message("Killing.");
        
        // Gracefully killing by waiting for notify_vp_finished(), after simulation is finished.
        if(gracefully){
            m_kill_server = true;
        }else{
            // Stopping immediately.
            shutdown();
        }

        return STATUS_OK;
    }

    bool avp64_testing_receiver::find_symbol_address(vcml::u64* addr, string &name, bool set_breakpoint){

        // Searches all targets for a address by the symbole name
 
        const symbol* sym_ptr = static_cast<vcml::debugging::target*>(target_core)->symbols().find_symbol(name);
        if(sym_ptr){
            *addr = sym_ptr->virt_addr();
            // Sets a breakpoint to this address if set_breakpoint is set.
            // This sets a breakpoint without beeing managed by active_breakpoint vectors (used for example by run_until mode).
            if(set_breakpoint){
                return set_breakpoint_to_address(*addr);
            }
            return true;
        }
        return false;
    }

    bool avp64_testing_receiver::set_breakpoint_to_address(vcml::u64 addr){
        log_info_message("Setting breakpoint to address 0x%016llx.", (int)addr);
        if(!static_cast<vcml::debugging::target*>(target_core)->insert_breakpoint(addr, this)){
            log_error_message("Failed to insert the breakpoint!", addr);
            return false;
        }

        return true;
    }

    bool avp64_testing_receiver::remove_breakpoint_from_address(vcml::u64 addr){
        log_info_message("Removing breakpoint from address %d.", (int)addr);
        if(!static_cast<vcml::debugging::target*>(target_core)->remove_breakpoint(addr, this)){
            log_error_message("Failed to remove the breakpoint at address %d!", addr);
            return false;
        }

        return true;
    }

    std::vector<avp64_testing_receiver::breakpoint>::iterator avp64_testing_receiver::find_breakpoint(string name){
        auto it = std::find_if(m_active_breakpoints.begin(), m_active_breakpoints.end(), 
                                [&sn = name] (const breakpoint& bp)-> bool { return sn == bp.name;});
        return it;
    }

    std::vector<avp64_testing_receiver::breakpoint>::iterator avp64_testing_receiver::find_breakpoint(mwr::u64 addr){
        auto it = std::find_if(m_active_breakpoints.begin(), m_active_breakpoints.end(), 
                                [&sa = addr] (const breakpoint& bp)-> bool { return sa == bp.addr;});
        return it;
    }

    void avp64_testing_receiver::remove_breakpoint(mwr::u64 addr, int vector_idx)
    {
        static_cast<vcml::debugging::target*>(target_core)->remove_breakpoint(addr,this);
        
        m_active_breakpoints.erase(m_active_breakpoints.begin() + vector_idx);
        log_info_message("Breakpoint at address %d removed.", addr);
    }

    status avp64_testing_receiver::handle_set_breakpoint(string &sym_name, int offset) {
        // Synchronize access to the active breakpoint vector, because it may access by multiple threads (simulation and receiving loop).
        std::lock_guard<std::mutex> lock(m_active_breakpoints_mutex);

        // Sets breakpoint by the symbole name and an offset.
        auto it = find_breakpoint(sym_name);

        // If the breakpoint is not already set
        if(it != m_active_breakpoints.end()){
            log_info_message("Breakpoint at symbol %s already set!", sym_name.c_str());
        }

        // Get the symbol of the eg main from the symbols' list
        const symbol* sym_ptr = static_cast<vcml::debugging::target*>(target_core)->symbols().find_symbol(sym_name);
        mwr::u64 sym_addr;

        // Check if symbol exist.
        if(!sym_ptr){
            log_error_message("Breakpoints symbol %s not found!", sym_name.c_str());
            return STATUS_ERROR;
        }
        
        sym_addr = sym_ptr->virt_addr() + offset;
        
        // Check if virt_addr() worked.
        if(!sym_addr){
            log_error_message("Failed to retrieve the breakpoints symbol %s virtual address!", sym_name.c_str());
            return STATUS_ERROR;
        }

        // Check if insertion worked.
        if(!static_cast<vcml::debugging::target*>(target_core)->insert_breakpoint(sym_addr, this)){ 
            log_error_message("Failed to insert the breakpoint at symbol %s!", sym_name.c_str());
            return STATUS_ERROR;
        }

        // Adding breakpoint to active breakpoint vector.
        m_active_breakpoints.push_back({sym_ptr, sym_name, sym_addr});
        log_info_message("Breakpoint set to %s with offset %d.", sym_name.c_str(), offset);

        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_remove_breakpoint(string &sym_name){
        // Synchronize access to the active breakpoint vector, because it may access by multiple threads (simulation and receiving loop).
        std::lock_guard<std::mutex> lock(m_active_breakpoints_mutex);

        auto it = find_breakpoint(sym_name);

        // If the breakpoint was found
        if(it != m_active_breakpoints.end()){
            remove_breakpoint((*it).addr, it - m_active_breakpoints.begin());

            return STATUS_OK;
        }else{
            log_error_message("Breakpoint at symbol %s was not set!", sym_name.c_str());
        }
        
        return STATUS_ERROR;
    }

    status avp64_testing_receiver::handle_enable_mmio_tracking(uint64_t start_address, uint64_t end_address, char mode){
        // Enabling MMIO tracking.
        m_mmio_probe->enable_tracking(start_address, end_address, (mmio_probe::tracking_mode)mode);
        log_info_message("MMIO tracking enabled between %d and %d with mode %d.", start_address, end_address, (uint8_t)mode);
        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_disable_mmio_tracking(){
        // Disabling MMIO tracking.
        m_mmio_probe->disable_tracking();
        log_info_message("MMIO tracking disabled.");
        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_set_mmio_value(size_t length, char* value)
    {
        mmio_event* first_mmio_event = nullptr;

        {
            // Synchronize access to the mmio event queue vector, because it may access by multiple threads (simulation and receiving loop).
            std::lock_guard<std::mutex> lock(m_mmio_event_queue_mutex);
            
            if(!m_mmio_event_queue.empty()) first_mmio_event = &m_mmio_event_queue.front();
        }

        // Check if there is a mmio event.
        if(first_mmio_event == nullptr){
            log_info_message("There is currently no MMIO read/write waiting for data!");
            return STATUS_ERROR;
        }

        // Check if the length of the data in the request matches the length of the mmio request (with offset).
        if(length != first_mmio_event->length){
            log_info_message("The length of the data of this request %d does not match the length of the mmio event payload %d (type: %d)!", length, first_mmio_event->length, (uint8_t)first_mmio_event->cmd);
            return STATUS_ERROR;
        }

        // Writing data to the mmio event payload.
        memcpy(first_mmio_event->ptr, value, first_mmio_event->length);

        log_info_message("Successful set of MMIO data to: %d (type: %d).", (int)first_mmio_event->mmio_addr, (uint8_t)first_mmio_event->cmd);

        // Notify the mutex to let on_mmio_access finish the execution.
        sem_post(first_mmio_event->mutex);

        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_add_to_mmio_read_queue(uint64_t address, size_t length, size_t data_length, char* data){
        // Adding to MMIO read queue of the mmio probe.
        m_mmio_probe->add_to_read_queue(address, length, data_length, data);
        
        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_set_cpu_interrupt_trigger(uint64_t interrupt_address, uint64_t trigger_address){
        if(target_core->set_interrupt_trigger(interrupt_address, trigger_address) && set_breakpoint_to_address(trigger_address)){
            return STATUS_OK;
        }else{
            return STATUS_ERROR;
        }
    }

    status avp64_testing_receiver::handle_enable_code_coverage(){
        // Enabling basic block tracking for all targets.
        static_cast<vcml::debugging::target*>(target_core)->trace_basic_blocks(this);
        log_info_message("Code coverage enabled.");
        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_reset_code_coverage(){
        reset_code_coverage();
        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_disable_code_coverage(){
        // Disabling basic block tracking for all targets.
        static_cast<vcml::debugging::target*>(target_core)->untrace_basic_blocks(this);
        log_info_message("Code coverage disabled.");
        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_get_code_coverage(string* coverage){
        // Forward the coverage generation to the default testing receiver.
        *coverage = get_code_coverage();
        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_set_return_code_address(uint64_t address, std::string &reg_name){
        // Enabling recording of return address by setting the variables.
        m_ret_address = address;
        m_ret_recording_enabled = true;
        m_ret_register = reg_name;
        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_get_return_code(uint64_t &code){   
        // Check if return code was recorded.
        if(!m_ret_value_set){
            log_error_message("Return code was not recorded yet!");
            return STATUS_ERROR;
        }

        log_info_message("Getting return code of %d.", m_ret_value);
        
        // Resetting the recorded indicator.
        m_ret_value_set = false;
        
        code = m_ret_value;
        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_do_run(std::string &start_breakpoint, std::string &end_breakpoint, uint64_t mmio_address, size_t mmio_length, size_t mmio_data_length, char* mmio_data, std::string &register_name){   

        log_info_message("Do run from start breakpoint %s to end breakpoint %s with MMIO address %d and length %d.", start_breakpoint.c_str(), end_breakpoint.c_str(), mmio_address, mmio_length);

        event last_event;

        // Get current PC.
        uint64_t current_pc;
        handle_get_cpu_pc(current_pc);

        // Only continue until start breakpoint if one is specified and the last breakpoint and last breakpoint address differ to the current one (if not this indicates that a do_run was executed before and the execution is already at the start breakpoint). 
        if(start_breakpoint != "" && !(last_start_breakpoint == start_breakpoint && current_pc == last_start_breakpoint_addr)){

            log_info_message("Setting start breakpoint.");

            if(!find_symbol_address(&last_start_breakpoint_addr, start_breakpoint, true)){
                log_error_message("Start breakpoint was not found!");
                return STATUS_ERROR;
            }

            last_start_breakpoint = start_breakpoint;

            m_run_until_breakpoint_addr = last_start_breakpoint_addr;
            m_run_until_breakpoint = true;

            // Continues the execution to the start breakpoint where the next run can be started.
            log_info_message("Continuing until start breakpoint.");
            handle_continue(last_event);

            remove_breakpoint_from_address(last_start_breakpoint_addr);

            if(last_event.event != event_type::BREAKPOINT_HIT){
                log_error_message("Stopped not at the expected breakpoint!");

                if(last_event.event == event_type::VP_END){
                    log_error_message("VP finished before the start breakpoint!");
                }

                // Resetting and returning error
                m_run_until_breakpoint = false;
                m_ret_recording_enabled = false;
                return STATUS_ERROR;
            }

            handle_store_cpu_register();
        }

        // Setting the read queue to our mmio data, so its used without suspending MMIO events.
        m_mmio_probe->set_read_queue(mmio_address, mmio_length, mmio_data_length, mmio_data);

        // Setting end breakpoint. It is asumed here, that the simulation is currently at the start breakpoint or similar (somewhere before the target MMIO access).
        // The end breakpoint is set with run_until, which means that every event is ignored that is not the end breakpoint hit. This makes the execution much faster. The MMIO read queue will still be used. But if the target program requests more data than there is in the read queue this MMIO read event will also be ignored. If then the target program never hits the end breakpoint a infinite loop is then created here!
        log_info_message("Setting end breakpoint.");

        if(!find_symbol_address(&m_run_until_breakpoint_addr, end_breakpoint, true)){
            log_error_message("End breakpoint was not found!");

            // Resetting and returning error
            m_mmio_probe->delete_read_queue(mmio_address);
            return STATUS_ERROR;
        }
        m_run_until_breakpoint = true;

        // Set m_exit_breakpoint_address, so the exit code is still recorded.
        m_ret_address = m_run_until_breakpoint_addr;
        m_ret_recording_enabled = true;

        // Setting return register.
        m_ret_register = register_name;

        // Starts the run and the the next event should be the end breakpoint (run_until).
        handle_continue(last_event);

        //TODO add timeout!
        
        // If there was a different event, then an error occured.
        if(last_event.event != event_type::BREAKPOINT_HIT){

            if(last_event.event == event_type::ERROR_SYMBOL_HIT){

                m_ret_value = 1;
                m_ret_value_set = true;

            }else{

                log_error_message("Stopped not at the expected breakpoint!");

                if(last_event.event == event_type::VP_END){
                    log_error_message("VP finished before the end breakpoint!");
                }
    
                // Resetting and returning error
                m_run_until_breakpoint = false;
                m_ret_recording_enabled = false;
                m_mmio_probe->delete_read_queue(mmio_address);
                return STATUS_ERROR;
            }
        }


        if(last_start_breakpoint != ""){
            handle_restore_cpu_register();
        
            // Continues the execution to the start breakpoint where the next run can be started.
            log_info_message("Jumping to start address %d.", last_start_breakpoint_addr);
            target_core->jump_to(last_start_breakpoint_addr);
        }

        // Resetting run_until and the MMIO read queue.
        m_run_until_breakpoint = false;
        m_ret_recording_enabled = false;
        m_mmio_probe->delete_read_queue(mmio_address);

        return STATUS_OK;
    }

    void avp64_testing_receiver::shutdown(){
        log_error_message("Shutting down!");
        shutdown();
    }

    void avp64_testing_receiver::suspend_simulation(){
        if(!m_is_sim_suspended){
            m_is_sim_suspended = true;
            suspend();
        }
    }

    void avp64_testing_receiver::resume_simulation(){
        if(m_is_sim_suspended){
            m_is_sim_suspended = false;
            resume();
        }
    }

    bool avp64_testing_receiver::read_reg_value(uint64_t &read_val, string &reg_name){
        // Reading cpu register of the target core.
        const cpureg *reg = target_core->find_cpureg(reg_name);

        if(!reg){
            log_info_message("The register with the name %s was not found!", reg_name.c_str());
            return false;
        }

        if(reg->size > 8){
            log_error_message("The requested register is larger thatn 8 bytes, not supported!");
            return false;
        }
        reg->read(&read_val, reg->size);
        
        return true;
    }

    status avp64_testing_receiver::handle_set_error_symbol(std::string &symbol){

        if(find_symbol_address(&error_symbol_address, symbol, true)){
            return STATUS_OK;
        }else{
            return STATUS_ERROR;
        }
    }

    status avp64_testing_receiver::handle_set_fixed_read(size_t count, char* data){

        for(size_t i=0; i<count; i++){
            uint64_t address = testing_communication::bytes_to_int64(data, i*9);
            m_mmio_probe->set_fixed_read(address, data[i*9+8]);
        }

        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_get_cpu_pc(uint64_t &pc){

        pc = target_core->get_actual_pc();
        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_jump_cpu_to(uint64_t address){

        if(!testing::testing_communication::check_cast_to_uint32(address)){
            log_error_message("Address does not fit 32bit and thus is not supported by the CPU!");
            return STATUS_ERROR;
        }

        target_core->jump_to((uint32_t)address);
        return STATUS_OK;
    }

    status avp64_testing_receiver::handle_store_cpu_register(){

        if(target_core->store_registers()){
            return STATUS_OK;
        }else{
            return STATUS_ERROR;
        }
    }

    status avp64_testing_receiver::handle_restore_cpu_register(){
    
        target_core->request_restore_registers();
        return STATUS_OK;
    }

};