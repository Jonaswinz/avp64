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

    void mmio_probe::set_read_queue(uint64_t address, size_t length, size_t data_length, char* data){
        // Synchronize access to the queues, because it may access by multiple threads (simulation and receiving loop).
        std::lock_guard<std::mutex> lock(m_read_queues_mutex);

        // Delete the read queue if already exist.
        auto it = m_read_queues.find(address);
        if (it != m_read_queues.end()) {    
            delete_read_queue(address);
        }

        // Creating new memory location for the queue and copying data over.
        char* queue_data = (char*)malloc(data_length);
        memcpy(queue_data, data, data_length);
        // Add to read queues.
        m_read_queues[address] = read_queue{length, data_length, 0, queue_data};
    }

    void mmio_probe::add_to_read_queue(uint64_t address, size_t length, size_t data_length, char* data){
        // Synchronize access to the queues, because it may access by multiple threads (simulation and receiving loop).
        std::lock_guard<std::mutex> lock(m_read_queues_mutex);

        auto it = m_read_queues.find(address);
        if (it != m_read_queues.end()) {    
            // Calculating remaning data length of the current read queue.
            size_t remaining_length = it->second.data_length-it->second.data_index;
            // Creating new memory for the remaining data and new data and copying both to the new memory location.
            char* new_queue_data = (char*)malloc(remaining_length+data_length);
            memcpy(new_queue_data, it->second.data+it->second.data_index, remaining_length);
            memcpy(new_queue_data+remaining_length, data, data_length);
            // Freeing the old data
            free(it->second.data);
            // Updating the read queue.
            it->second.data = new_queue_data;
            it->second.data_length = remaining_length+data_length;
            it->second.data_index = 0;

        }else{
            // Set a new read queue, because it does not exist for the address yet.
            set_read_queue(address, length, data_length, data);
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

    void mmio_probe::set_fixed_read(uint64_t address, char data){
        // Synchronize access to fixed reads, because it may access by multiple threads (simulation and receiving loop).
        std::lock_guard<std::mutex> lock(m_fixed_reads_mutex);

        auto it = m_fixed_reads.find(address);
        if (it != m_fixed_reads.end()) {
            // Update fixed read data if exist.
            it->second.data = data;
        }else{
            // Add fixed read.
            m_fixed_reads[address] = fixed_read{data};
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

        // Array indicating which bytes of the request are filled.
        bool byte_set[tx.get_data_length()] = {false};

        // Checking fixed reads if there are any but only if command is a read.
        if(tx.get_command() == tlm::TLM_READ_COMMAND && m_fixed_reads.size() > 0){
            // Synchronize access to fixed reads, because it may access by multiple threads (simulation and receiving loop).
            std::lock_guard<std::mutex> lock(m_fixed_reads_mutex);

            // Writing fixed read values to data if fit.
            for (auto it = m_fixed_reads.begin(); it != m_fixed_reads.end(); ++it) {
                if(it->first >= tx.get_address() && it->first <= tx.get_address()+tx.get_data_length()){
                    vcml::log_info("MMIO_PROBE: Using fixed read for %lu with value %02X.", it->first, it->second.data);

                    // Wiring the byte to the request data by its offset.
                    uint64_t offset = it->first-tx.get_address();
                    memcpy(tx.get_data_ptr()+offset, &it->second.data, 1);

                    // Mark the byte as written.
                    byte_set[offset] = true;
                }
            }
        }

        //vcml::log_info("MMIO_PROBE: MMIO event for address 0x%016llx and length %d (%d)", (unsigned long long)tx.get_address(), (int)tx.get_data_length(), (int)tx.get_command());

        // If we're tracking the accesses we're not forwarding the payload to the system bus
        // The address must be inside the range defined tracking range and the mode must match the command of the transfer.
        // Ignoring simdev location of 0x10008000
        if(m_tracking_enabled && tx.get_address() != 0x10008000 && tx.get_address() >= m_tracking_start_address && tx.get_address() <= m_tracking_end_address && (m_tracking_mode == FULL_TRACKING || (m_tracking_mode == READ_TRACKING && tx.get_command() == tlm::TLM_READ_COMMAND) || (m_tracking_mode == WRITE_TRACKING && tx.get_command() == tlm::TLM_WRITE_COMMAND))){

            //vcml::log_info("MMIO_PROBE: MMIO event intercepted for address 0x%016llx and length %d (%d)", (unsigned long long)tx.get_address(), (int)tx.get_data_length(), (int)tx.get_command());

            // Check if this is a read and there is data in the read queue. Otherwise forward the request to the testing_received, which will suspend the simulation and trigger a event.
            if(tx.get_command() == tlm::TLM_READ_COMMAND){

                if(m_read_queues.size() > 0){
                    // Synchronize access to the queues, because it may access by multiple threads (simulation and receiving loop).
                    std::lock_guard<std::mutex> lock(m_read_queues_mutex);

                    // Check all read queues if in the current address range.
                    for (auto it = m_read_queues.begin(); it != m_read_queues.end(); ) {

                        if(it->first >= tx.get_address() && it->first <= tx.get_address()+tx.get_data_length()){
                            
                            uint64_t offset = it->first-tx.get_address();
                            size_t queue_available = it->second.data_length-it->second.data_index;

                            // The used data of the queue is the specified length or less, depending how much is available.
                            size_t fill_length = std::min(queue_available, it->second.length);

                            // If the request is shorter than the fill_length adjust it.
                            if(offset+fill_length > tx.get_data_length()) fill_length = tx.get_data_length()-offset;

                            vcml::log_info("MMIO_PROBE: Reading from %d read queue %lu characters.", (int)tx.get_address(), fill_length);
                            vcml::log_info("MMIO_PROBE: Value: %s", it->second.data+it->second.data_index);
                            
                            // Copy data and update queue index.
                            memcpy(tx.get_data_ptr()+offset, it->second.data+it->second.data_index, fill_length);
                            it->second.data_index += fill_length;

                            // Mark the bytes as written.
                            for(size_t i = 0; i<fill_length; i++){
                                byte_set[offset+i] = true;
                            }

                            // Remove the read queue when it was emptied!
                            // TODO: Move this somehwere else, to make it more performant.
                            if(it->second.data_index == it->second.data_length){
                                free(it->second.data);
                                it = m_read_queues.erase(it);
                            }else{
                                ++it;
                            }
                        }
                    }
                }

                // Checking if the whole request was filled by the read queues and fixed reads. If not trigger an MMIO event for the missing chunks.
                bool empty_chunk_found = false;
                size_t empty_chunk_start = 0;
                for(size_t i=0; i<tx.get_data_length(); i++){
                    if(byte_set[i] == false && !empty_chunk_found){
                        empty_chunk_start = i;
                        empty_chunk_found = true;
                    }else if(byte_set[i] == true && empty_chunk_found){
                        notify_mmio_access(tx.get_command(), tx.get_data_ptr()+empty_chunk_start, tx.get_address()+empty_chunk_start, i-empty_chunk_start);
                        empty_chunk_found = false;
                    }
                }
                // Check the last chunk.
                if(empty_chunk_found){
                    notify_mmio_access(tx.get_command(), tx.get_data_ptr()+empty_chunk_start, tx.get_address()+empty_chunk_start, tx.get_data_length()-empty_chunk_start);
                }

                tx.set_response_status(tlm::TLM_OK_RESPONSE);

                // Do not forward to the bus here, because the read was fully intercepted!

            }else if(tx.get_command() == tlm::TLM_WRITE_COMMAND){
                // A write request
                // Calls avp64_testing_receiver::on_mmio_access() to trigger a MMIO event.
                notify_mmio_access(tx.get_command(), tx.get_data_ptr(), tx.get_address(), tx.get_data_length());
                tx.set_response_status(tlm::TLM_OK_RESPONSE);

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