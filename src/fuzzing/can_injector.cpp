#include "fuzzing/can_injector.h"

namespace fuzzing{

void Can_injector::can_transmit() {
    while (true) {
        wait(m_ev);

        std::lock_guard<std::mutex> guard(m_mtx);
        while (!m_rx.empty()) {
            vcml::can_frame frame = m_rx.front();
            m_rx.pop();
            can_tx.send(frame);
        }
    }
}

void Can_injector::send_to_guest(vcml::can_frame frame) {
    std::lock_guard<std::mutex> guard(m_mtx);
    m_rx.push(frame);
    vcml::on_next_update([&]() -> void { m_ev.notify(sc_core::SC_ZERO_TIME); });
}

Can_injector::Can_injector(const sc_core::sc_module_name& nm):
    module(nm),
    m_mtx(),
    m_rx(),
    m_ev("rxev"),
    can_tx("can_tx"),
    can_rx("can_rx")
{

    SC_HAS_PROCESS(Can_injector);
    SC_THREAD(can_transmit);

}

Can_injector::~Can_injector() {}

}