#include "testing/mmio_probe.h"

namespace testing {

    mmio_probe::mmio_probe(const vcml::sc_module_name& nm):
        vcml::component(nm),
        probe_in("probe_in"),
        probe_out("probe_out"){}

    void mmio_probe::reset() {
        component::reset();
    }

    void mmio_probe::enable_tracking(uint64_t start_address, uint64_t end_address, tracking_mode mode){
        m_tracking_enabled = true;
        m_tracking_start_address = start_address;
        m_tracking_end_address = end_address;
        m_tracking_mode = mode;
    }

    void mmio_probe::disable_tracking(){
        m_tracking_enabled = false;
    }

    void mmio_probe::set_read_queue(uint64_t address, size_t length, char* data){
        // Synchronize access to the queues, because it may access by multiple threads (simulation and receiving loop).
        std::lock_guard<std::mutex> lock(m_read_queues_mutex);

        // Delete the read queue if already exist.
        auto it = m_read_queues.find(address);
        if (it != m_read_queues.end()) {    
            delete_read_queue(address);
        }

        // Creating new memory location for the queue and copying data over.
        char* queue_data = (char*)malloc(length);
        memcpy(queue_data, data, length);
        // Add to read queues.
        m_read_queues[address] = read_queue{length, 0, queue_data};
    }

    void mmio_probe::add_to_read_queue(uint64_t address, size_t length, char* data){
        // Synchronize access to the queues, because it may access by multiple threads (simulation and receiving loop).
        std::lock_guard<std::mutex> lock(m_read_queues_mutex);

        auto it = m_read_queues.find(address);
        if (it != m_read_queues.end()) {    
            // Calculating remaning data length of the current read queue.
            size_t remaining_length = it->second.data_length-it->second.data_index;
            // Creating new memory for the remaining data and new data and copying both to the new memory location.
            char* new_queue_data = (char*)malloc(remaining_length+length);
            memcpy(new_queue_data, it->second.data+it->second.data_index, remaining_length);
            memcpy(new_queue_data+remaining_length, data, length);
            // Freeing the old data
            free(it->second.data);
            // Updating the read queue.
            it->second.data = new_queue_data;
            it->second.data_length = remaining_length+length;
            it->second.data_index = 0;

        }else{
            // Set a new read queue, because it does not exist for the address yet.
            set_read_queue(address, length, data);
        }

    }

    void mmio_probe::delete_read_queue(uint64_t address){
        //Synchronize access to the queues, because it may access by multiple threads (simulation and receiving loop).
        std::lock_guard<std::mutex> lock(m_read_queues_mutex);

        auto it = m_read_queues.find(address);
        if (it != m_read_queues.end()) {   
            free(it->second.data);
            m_read_queues.erase(it);
        }
    }

    void mmio_probe::before_end_of_elaboration() {
        component::before_end_of_elaboration();
        if (!clk.is_bound())
            clk.stub(100 * mwr::MHz);
        if (!rst.is_bound()) {
            rst.stub();
            reset();
        }
    }

    bool mmio_probe::get_direct_mem_ptr(vcml::tlm_target_socket& origin, vcml::tlm_generic_payload& tx, vcml::tlm_dmi& dmi) {
        bool use_dmi = probe_out->get_direct_mem_ptr(tx, dmi);

        if (use_dmi) {

            uint64_t s = dmi.get_start_address();
            uint64_t e = dmi.get_end_address();

            dmi.set_start_address(s);
            dmi.set_end_address(e);
        }

        return use_dmi;
    }

    void mmio_probe::b_transport(vcml::tlm_target_socket& origin, vcml::tlm_generic_payload& tx, vcml::sc_time& dt){
        // Error checking
        VCML_ERROR_ON(tx.get_data_ptr() == nullptr, "Transaction data pointer cannot be null");
        VCML_ERROR_ON(tx.get_data_length() == 0, "Transaction data length cannot be zero");
        VCML_ERROR_ON(tx.get_response_status() != vcml::TLM_INCOMPLETE_RESPONSE, "Invalid in-bound transaction response status");

        // If we're tracking the accesses we're not forwarding the payload to the system bus
        // The address must be inside the range defined tracking range and the mode must match the command of the transfer.
        // Ignoring simdev location of 0x10008000
        if(m_tracking_enabled && tx.get_address() != 0x10008000 && tx.get_address() >= m_tracking_start_address && tx.get_address() <= m_tracking_end_address && (m_tracking_mode == FULL_TRACKING || (m_tracking_mode == READ_TRACKING && tx.get_command() == tlm::TLM_READ_COMMAND) || (m_tracking_mode == WRITE_TRACKING && tx.get_command() == tlm::TLM_WRITE_COMMAND))){

            // Check if this is a read and there is data in the read queue. Otherwise forward the request to the testing_received, which will suspend the simulation and trigger a event.
            if(tx.get_command() == tlm::TLM_READ_COMMAND){

                //Synchronize access to the queues, because it may access by multiple threads (simulation and receiving loop).
                std::lock_guard<std::mutex> lock(m_read_queues_mutex);

                auto it = m_read_queues.find(tx.get_address());
                if (it != m_read_queues.end()) {    

                    size_t queue_available = it->second.data_length-it->second.data_index;

                    if(tx.get_data_length() <= queue_available){
                    
                        vcml::log_info("Reading from %d read queue %d characters.", (int)tx.get_address(), (int)tx.get_data_length());
                        vcml::log_info("Value: %s", it->second.data+it->second.data_index);

                        memcpy(tx.get_data_ptr(), it->second.data+it->second.data_index, tx.get_data_length());
                        it->second.data_index += tx.get_data_length();

                        // Setting the status directly, in the other cases its done when handling the request (before notify_mmio_access returnes).
                        tx.set_response_status(tlm::TLM_OK_RESPONSE);
                
                    }else{

                        vcml::log_info("Reading from %d read queue only %d characters (%d required).", (int)tx.get_address(), (int)queue_available, (int)tx.get_data_length());
                        vcml::log_info("Value: %s", it->second.data+it->second.data_index);

                        memcpy(tx.get_data_ptr(), it->second.data+it->second.data_index, queue_available);
                        it->second.data_index += queue_available;

                        // Request is longer than the available data in the read queue.
                        // Calls avp64_testing_receiver::on_mmio_access() to trigger a MMIO event, but only for the remaining data.
                        notify_mmio_access(tx, queue_available);
                    }

                    // Remove the read queue when it was emptied!
                    // TODO: Move this somehwere else, to make it more performant.
                    if(tx.get_data_length() > queue_available){
                        free(it->second.data);
                        m_read_queues.erase(it);
                    }
                        
                }else{
                    // Address not found in read queues.
                    // Calls avp64_testing_receiver::on_mmio_access() to trigger a MMIO event.
                    notify_mmio_access(tx, 0);
                }

                // Check if the status was set to TLM_OK_RESPONSE after the event or read queue usage.
                if (tx.get_response_status() != vcml::TLM_OK_RESPONSE){
                    VCML_ERROR("invalid in-bound transaction response status");
                }

                // Do not forward to the bus here, because the read was fully intercepted!

            }else if(tx.get_command() == tlm::TLM_WRITE_COMMAND){
                // A write request
                // Calls avp64_testing_receiver::on_mmio_access() to trigger a MMIO event.
                notify_mmio_access(tx, 0);

                // Check if the status was set to TLM_OK_RESPONSE after the event or read queue usage.
                if (tx.get_response_status() != vcml::TLM_OK_RESPONSE){
                    VCML_ERROR("invalid in-bound transaction response status");
                }

                // Forward to the bus, because the modified write still need to be executed.
                probe_out.b_transport(tx, dt); 

            }else{

                // Forward every other command type to the bus.
                probe_out.b_transport(tx, dt); 
            }

        }else{

            // Forward to the bus, because the interception is not enabled or the interception settings does not fit this request.
            probe_out.b_transport(tx, dt); 
        }
    }

    unsigned int mmio_probe::transport_dbg(vcml::tlm_target_socket& origin, vcml::tlm_generic_payload& tx) {
        return probe_out->transport_dbg(tx);
    }
}