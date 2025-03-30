#ifndef PROBE_H
#define PROBE_H

#include <mutex> 
#include <condition_variable> 
#include <unordered_map>
#include "vcml/core/component.h"

namespace testing{

    class mmio_probe : public vcml::component
    {
        public:

            // Available tracking modes.
            enum tracking_mode{
                FULL_TRACKING, READ_TRACKING, WRITE_TRACKING
            };

            // Represents a MMIO read queue.
            struct read_queue{
                size_t length;
                size_t data_length;
                size_t data_index;
                char* data;
            };

            struct fixed_read{
                char data;
            };

            // In and output socket of this VCML component.
            vcml::tlm_target_socket probe_in;
            vcml::tlm_initiator_socket probe_out;

            // Creates this MMIO probe with a SystemC name.
            mmio_probe(const vcml::sc_module_name& nm);

            // Implementation of vcml::components reset method.
            void reset() override;

            // Enables tracking in general between two addresses and for a given mode.
            void enable_tracking(uint64_t start_address, uint64_t end_address, tracking_mode mode);

            // Disables the tracking.
            void disable_tracking();

            // Variable for the callback when an MMIO access needs to be handeled. Should be set to the testing_receiver.
            std::function<void(tlm::tlm_command cmd, unsigned char* ptr, uint64_t mmio_addr, unsigned int length)> notify_mmio_access = NULL;

            // Sets a new MMIO read queue.
            void set_read_queue(uint64_t address, size_t length, size_t data_length, char* data);

            // Adds to an existing MMIO read queue.
            void add_to_read_queue(uint64_t address, size_t length, size_t data_length, char* data);

            // Deletes and existing MMIO read queue.
            void delete_read_queue(uint64_t address);

            // Adds a fixed read entry.
            void set_fixed_read(uint64_t address, char data);

        protected:

            // Implementation of vcml::components before_end_of_elaboration method.
            void before_end_of_elaboration() override;

        private:

            // Implementation of vcml::components reset method.
            bool get_direct_mem_ptr(vcml::tlm_target_socket& origin, vcml::tlm_generic_payload& tx, vcml::tlm_dmi& dmi_data) override;
            
            // Implementation of vcml::components b_transport method. Here the MMIO interception takes place.
            void b_transport(vcml::tlm_target_socket& origin, vcml::tlm_generic_payload& tx, vcml::sc_time& dt) override;
            
            // Implementation of vcml::components transport_dbg method.
            unsigned int transport_dbg(vcml::tlm_target_socket& origin, vcml::tlm_generic_payload& tx) override;

            // Settings for the tracking
            bool m_tracking_enabled = false;
            uint64_t m_tracking_start_address = 0;
            uint64_t m_tracking_end_address = 0;
            tracking_mode m_tracking_mode;
            
            // Management of the different read queues.
            std::unordered_map<uint64_t, read_queue> m_read_queues;
            std::mutex m_read_queues_mutex;

            // Management of fixed reads.
            std::unordered_map<uint64_t, fixed_read> m_fixed_reads;
            std::mutex m_fixed_reads_mutex;
    };

} //namespace testing

#endif
