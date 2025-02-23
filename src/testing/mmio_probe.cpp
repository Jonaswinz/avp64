#include "testing/mmio_probe.h"

namespace testing {

    mmio_probe::mmio_probe(const vcml::sc_module_name& nm):
    vcml::component(nm),
    probe_in("probe_in"),
    probe_out("probe_out"){}

    void mmio_probe::b_transport(vcml::tlm_target_socket& origin, vcml::tlm_generic_payload& tx, vcml::sc_time& dt)
    {
        unsigned char* ptr = tx.get_data_ptr();
        unsigned int length = tx.get_data_length();

        VCML_ERROR_ON(ptr == nullptr, "transaction data pointer cannot be null");
        VCML_ERROR_ON(length == 0, "transaction data length cannot be zero");

        if (tx.get_response_status() != vcml::TLM_INCOMPLETE_RESPONSE)
            VCML_ERROR("invalid in-bound transaction response status");

        // If we're tracking the accesses we're not forwarding the payload to the system bus
        // The address must be inside the range defined tracking range and the mode must match the command of the transfer.
        // Ignoring simdev location of 0x10008000
        if(m_tracking_enabled && tx.get_address() != 0x10008000 && tx.get_address() >= m_tracking_start_address && tx.get_address() <= m_tracking_end_address && (m_tracking_mode == FULL_TRACKING || (m_tracking_mode == READ_TRACKING && tx.get_command() == tlm::TLM_READ_COMMAND) || (m_tracking_mode == WRITE_TRACKING && tx.get_command() == tlm::TLM_WRITE_COMMAND))){

            // Check if this is a read and there is data in the read queue. Otherwise forward the request to the testing_received, which will suspend the simulation and trigger a event.
            if(tx.get_command() == tlm::TLM_READ_COMMAND && m_read_queue != nullptr && m_read_queue_index < m_read_queue_length){
                
                // TODO implement new queue method!!!

                size_t queue_available = m_read_queue_length-m_read_queue_index;

                if(tx.get_data_length() <= queue_available){
                    
                    vcml::log_info("Reading from read queue %d characters.", (int)tx.get_data_length());
                    vcml::log_info("Value: %s", m_read_queue+m_read_queue_index);

                    memcpy(tx.get_data_ptr(), m_read_queue+m_read_queue_index, tx.get_data_length());
                    m_read_queue_index += tx.get_data_length();

                    vcml::log_info("Index %d, length %d.", (int)m_read_queue_index, (int)m_read_queue_length);

                    tx.set_response_status(tlm::TLM_OK_RESPONSE);

                }else{
                    //TODO partially from queue !?
                }

            }else{
                notify_mmio_access(tx); // this calls test_gRPCserver::on_mmio_access()
            }

            // Check if the status was set to TLM_OK_RESPONSE after the event or read queue usage.
            if (tx.get_response_status() != vcml::TLM_OK_RESPONSE){
                VCML_ERROR("invalid in-bound transaction response status");
            }

        }else{
            // Forward to the bus.
            probe_out.b_transport(tx, dt); 
        }
    }

    unsigned int mmio_probe::transport_dbg(vcml::tlm_target_socket& origin,
                                    vcml::tlm_generic_payload& tx) {

        return probe_out->transport_dbg(tx);
    }

    bool mmio_probe::get_direct_mem_ptr(vcml::tlm_target_socket& origin,
                            vcml::tlm_generic_payload& tx, vcml::tlm_dmi& dmi) {
        bool use_dmi = probe_out->get_direct_mem_ptr(tx, dmi);

        if (use_dmi) {

            uint64_t s = dmi.get_start_address();
            uint64_t e = dmi.get_end_address();

            dmi.set_start_address(s);
            dmi.set_end_address(e);
        }

        return use_dmi;
    }

    void mmio_probe::reset() {
        component::reset();
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

    void mmio_probe::set_read_queue(char* queue_pointer, size_t length){
        m_read_queue = queue_pointer;
        m_read_queue_length = length;
        m_read_queue_index = 0;
    }

    void mmio_probe::reset_read_queue(){
        m_read_queue = nullptr;
        m_read_queue_length = 0;
        m_read_queue_index = 0;
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

}