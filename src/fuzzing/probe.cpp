#include "fuzzing/probe.h"

namespace fuzzing {

probe::probe(const vcml::sc_module_name& nm, fuzzing::MMIO_access& mmio_access):
vcml::component(nm),
probe_in("probe_in"),
probe_out("probe_out"),
mmio_access_ptr(&mmio_access){}

void probe::b_transport(vcml::tlm_target_socket& origin, vcml::tlm_generic_payload& tx, vcml::sc_time& dt)
{
    unsigned char* ptr = tx.get_data_ptr();
    unsigned int length = tx.get_data_length(); // this should be 1 byte

    VCML_ERROR_ON(ptr == nullptr, "transaction data pointer cannot be null");
    VCML_ERROR_ON(length == 0, "transaction data length cannot be zero");

    if (tx.get_response_status() != vcml::TLM_INCOMPLETE_RESPONSE)
        VCML_ERROR("invalid in-bound transaction response status");

    // If we're tracking the accesses we're not forwarding the payload to the system bus
    if(mmio_access_ptr->track_mmio_access)
    {
        notify_mmio_access(tx); // this calls test_gRPCserver::on_mmio_access()

        if (tx.get_response_status() != vcml::TLM_OK_RESPONSE)
            VCML_ERROR("invalid in-bound transaction response status");
    }
    else
        probe_out.b_transport(tx, dt); 
}

unsigned int probe::transport_dbg(vcml::tlm_target_socket& origin,
                                vcml::tlm_generic_payload& tx) {

    return probe_out->transport_dbg(tx);
}

bool probe::get_direct_mem_ptr(vcml::tlm_target_socket& origin,
                        vcml::tlm_generic_payload& tx, vcml::tlm_dmi& dmi)
{
    bool use_dmi = probe_out->get_direct_mem_ptr(tx, dmi);

    if (use_dmi) {

        uint64_t s = dmi.get_start_address();
        uint64_t e = dmi.get_end_address();

        dmi.set_start_address(s);
        dmi.set_end_address(e);
    }

    return use_dmi;
}

void probe::reset() {
    component::reset();
}

void probe::before_end_of_elaboration() {
    component::before_end_of_elaboration();
    if (!clk.is_bound())
        clk.stub(100 * mwr::MHz);
    if (!rst.is_bound()) {
        rst.stub();
        reset();
    }
}

}