#ifndef PROBE_H
#define PROBE_H

#include <mutex> 
#include <condition_variable> 
#include "vcml/core/component.h"

namespace testing{

    class mmio_probe : public vcml::component
    {
        public:

            enum tracking_mode{
                FULL_TRACKING, READ_TRACKING, WRITE_TRACKING
            };

            vcml::tlm_target_socket probe_in;
            vcml::tlm_initiator_socket probe_out;

            mmio_probe(const vcml::sc_module_name& nm);
            virtual void reset() override;

            std::function<void(vcml::tlm_generic_payload&)> notify_mmio_access = NULL;

            void set_read_queue(char* queue_pointer, size_t length);

            void reset_read_queue();

            void enable_tracking(uint64_t start_address, uint64_t end_address, tracking_mode mode);

            void disable_tracking();

        private:

            virtual bool get_direct_mem_ptr(vcml::tlm_target_socket& origin,
                                            vcml::tlm_generic_payload& tx, vcml::tlm_dmi& dmi_data) override;

            virtual void b_transport(vcml::tlm_target_socket& origin, 
                                    vcml::tlm_generic_payload& tx, vcml::sc_time& dt) override;
            virtual unsigned int transport_dbg(vcml::tlm_target_socket& origin,
                                    vcml::tlm_generic_payload& tx) override;

            char* m_read_queue = nullptr;
            size_t m_read_queue_index = 0;
            size_t m_read_queue_length = 0;

            bool m_tracking_enabled = false;
            uint64_t m_tracking_start_address = 0;
            uint64_t m_tracking_end_address = 0;
            tracking_mode m_tracking_mode;
            
        protected:
            virtual void before_end_of_elaboration() override;

    };

} //namespace testing

#endif
