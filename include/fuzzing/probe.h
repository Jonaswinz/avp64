#ifndef PROBE_H
#define PROBE_H

#include <mutex> 
#include <condition_variable> 
#include "vcml/core/component.h"

namespace fuzzing{

class MMIO_access
{
    public:
        MMIO_access(){}

        struct data{
            std::unique_ptr<unsigned char[]> value;
            uint32_t length;
            uint64_t addr = 0; 
            bool ready;
        };
        std::queue<data> write_data_buffer;
        data read_data;

        std::mutex mmio_data_mtx;
        std::condition_variable mmio_data_cv;

        bool track_mmio_access = false;

        ~MMIO_access(){}
};

class probe : public vcml::component
{
    public:
        vcml::tlm_target_socket probe_in;
        vcml::tlm_initiator_socket probe_out;

        probe(const vcml::sc_module_name& nm, MMIO_access& mmio_access);
        virtual void reset() override;

        std::function<void(vcml::tlm_generic_payload&)> notify_mmio_access = NULL;

    private:
        MMIO_access* mmio_access_ptr;

        virtual bool get_direct_mem_ptr(vcml::tlm_target_socket& origin,
                                        vcml::tlm_generic_payload& tx, vcml::tlm_dmi& dmi_data) override;

        virtual void b_transport(vcml::tlm_target_socket& origin, 
                                 vcml::tlm_generic_payload& tx, vcml::sc_time& dt) override;
        virtual unsigned int transport_dbg(vcml::tlm_target_socket& origin,
                                vcml::tlm_generic_payload& tx) override;
        
    protected:
        virtual void before_end_of_elaboration() override;

};

} //namespace fuzzing

#endif
