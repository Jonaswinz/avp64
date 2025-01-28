#include "fuzzing/test_interface.h"

namespace fuzzing{

    mq_test_interface::mq_test_interface(){
        m_attr.mq_flags = 0;
        m_attr.mq_maxmsg = 10;
        m_attr.mq_msgsize = REQUEST_LENGTH;
        m_attr.mq_curmsgs = 0;

        clear_mq("/avp64-test-receiver");
        clear_mq("/avp64-test-sender");

        if ((m_mqt_requests = mq_open("/avp64-test-receiver", O_RDONLY | O_CREAT, 0660, &m_attr)) == -1) {
            LOG_ERROR("Error opening request message queue %s.", mq_request_name.c_str());
            exit(1);
        }

        if ((m_mqt_responses = mq_open("/avp64-test-sender", O_WRONLY | O_CREAT, 0644, &m_attr)) == -1) {
            LOG_ERROR("Error opening response message queue %s.", mq_response_name.c_str());
            exit(1);
        }

        string ready_signal = "ready";
        if(mq_send(m_mqt_responses, ready_signal.c_str(), ready_signal.size(), 0) == 0){
            LOG_INFO("Message queues ready, waiting for requests.");
        }else{
            LOG_ERROR("Error sending ready message: %s.", strerror(errno));  
        }

    }

    mq_test_interface::~mq_test_interface(){
        mq_close(m_mqt_requests);
        mq_close(m_mqt_responses);
    }

    bool mq_test_interface::send_response(test_interface::response &req){

        if(mq_send(m_mqt_responses, req.data, req.data_length, 0) == -1){
            LOG_ERROR("Error sending response data: %s", strerror(errno));
            return false;
        }
        
        return true;
    }

    bool mq_test_interface::receive_request(){
        // Clear buffer
        memset(m_buffer, 0, sizeof(m_buffer));

        // Receive message
        size_t bytes_read = mq_receive(m_mqt_requests, m_buffer, REQUEST_LENGTH, NULL);
        if (bytes_read < 1) {
            LOG_ERROR("Message was too short for a valid request!");  
            return false;
        }

        m_current_req = request();

        m_current_req.data_length = bytes_read;
        m_current_req.cmd = (test_interface::command)m_buffer[0];
        if(bytes_read > 1) std::memcpy(&(m_current_req.data), m_buffer+1, bytes_read-1);

        return true;
    }

    test_interface::request mq_test_interface::get_request(){
        return m_current_req;
    }

    void mq_test_interface::clear_mq(const char* queue_name) {
        mqd_t mqd = mq_open(queue_name, O_RDONLY | O_NONBLOCK);
        if (mqd == -1) {
            return;
        }

        struct mq_attr attr;
        mq_getattr(mqd, &attr);
        char* buffer = new char[attr.mq_msgsize];

        while (true) {
            ssize_t bytes_read = mq_receive(mqd, buffer, attr.mq_msgsize, NULL);
            if (bytes_read == -1) {
                if (errno == EAGAIN) {
                    LOG_INFO("Message queue %s is now empty.", queue_name);
                    break;
                }
            }
        }

        delete[] buffer;
        mq_close(mqd);
    }

};