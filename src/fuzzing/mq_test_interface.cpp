#include "fuzzing/test_interface.h"

namespace fuzzing{

    mq_test_interface::mq_test_interface(string mq_request_name, string mq_response_name){
        m_mq_request_name = new char[mq_request_name.length() + 1];
        std::strcpy(m_mq_request_name, mq_request_name.c_str());
        m_mq_response_name = new char[mq_response_name.length() + 1];
        std::strcpy(m_mq_response_name, mq_response_name.c_str());
    }

    bool mq_test_interface::start(){

        m_attr.mq_flags = 0;
        m_attr.mq_maxmsg = 10;
        m_attr.mq_msgsize = MQ_REQUEST_LENGTH;
        m_attr.mq_curmsgs = 0;

        clear_mq(m_mq_request_name);
        clear_mq(m_mq_response_name);

        if ((m_mqt_requests = mq_open(m_mq_request_name, O_RDONLY | O_CREAT, 0660, &m_attr)) == -1) {
            LOG_ERROR("Error opening request message queue %s.", m_mq_request_name);
            return false;
        }

        if ((m_mqt_responses = mq_open(m_mq_response_name, O_WRONLY | O_CREAT, 0644, &m_attr)) == -1) {
            LOG_ERROR("Error opening response message queue %s.", m_mq_response_name);
            return false;
        }

        string ready_signal = "ready";
        if(mq_send(m_mqt_responses, ready_signal.c_str(), ready_signal.size(), 0) == 0){
            LOG_INFO("Communication ready, waiting for requests.");
        }else{
            LOG_ERROR("Error sending ready message: %s.", strerror(errno));  
            return false;
        }

        return true;
    }

    mq_test_interface::~mq_test_interface(){
        mq_close(m_mqt_requests);
        mq_close(m_mqt_responses);
    }

    bool mq_test_interface::send_response(test_interface::response &res){

        size_t sent_length = 0;

        // Send the response in multiple messages if the message is longer than RESPONSE_LENGTH
        while(sent_length < res.data_length){

            // Send the rest data or maximum RESPONSE_LENGTH much.
            size_t next_chunk = std::min(res.data_length - sent_length, (size_t)MQ_RESPONSE_LENGTH);

            if(mq_send(m_mqt_responses, res.data+sent_length, next_chunk, 0) == -1){
                LOG_ERROR("Error sending response data: %s", strerror(errno));
                return false;
            }

            sent_length += next_chunk;
        }
        
        return true;
    }

    bool mq_test_interface::receive_request(){
        // Clear buffer
        memset(m_buffer, 0, sizeof(m_buffer));

        // Receive message
        size_t bytes_read = mq_receive(m_mqt_requests, m_buffer, MQ_REQUEST_LENGTH, NULL);
        if (bytes_read < 1) {
            LOG_ERROR("Message was too short for a valid request!");  
            return false;
        }

        // Clear old data if existed.
        if(m_current_req.data != nullptr){
            free(m_current_req.data);
            m_current_req.data = nullptr;
        }

        m_current_req = request();
        m_current_req.data = (char*)malloc(bytes_read-1);
        m_current_req.data_length = bytes_read;
        m_current_req.cmd = (test_interface::command)m_buffer[0];
        if(bytes_read > 1) std::memcpy(m_current_req.data, m_buffer+1, bytes_read-1);

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