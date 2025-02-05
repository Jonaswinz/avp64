#ifndef CAN_INJECTOR_H
#define CAN_INJECTOR_H

#include <queue>
#include <mutex> 
#include "vcml/core/types.h"
#include "vcml/core/systemc.h"
#include "vcml/protocols/can.h"
#include "vcml/core/component.h"

namespace testing{

    class Can_injector : public vcml::module, public vcml::can_host
    {
        private:
            mutable std::mutex m_mtx;
            std::queue<vcml::can_frame> m_rx;
            vcml::sc_event m_ev;

            void can_transmit();
        
        public:
            vcml::can_initiator_socket can_tx;
            vcml::can_target_socket can_rx; //I need it to do connect it to the canbus, but I won't use it

            Can_injector(const sc_core::sc_module_name& nm);
            void send_to_guest(vcml::can_frame frame);

            ~Can_injector();
    };

} //namespace testing

#endif