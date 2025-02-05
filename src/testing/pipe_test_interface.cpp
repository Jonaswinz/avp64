#include "testing/test_interface.h"

namespace testing{

    pipe_test_interface::pipe_test_interface(int fd_requests, int fd_response){
        m_fd_request = fd_requests;
        m_fd_response = fd_response;
    }

    bool pipe_test_interface::start(){

        string ready = "ready";
        ssize_t written = write(m_fd_response, ready.c_str(), ready.size()+1);
        if (written != -1 && written == (ssize_t)ready.size()+1) {
            LOG_INFO("Communication ready, waiting for requests.");
        }else{
            LOG_ERROR("Error sending ready message: %s.", strerror(errno));  
            return false;
        }

        return true;
    }

    pipe_test_interface::~pipe_test_interface(){
        close(m_fd_request);
        close(m_fd_request);
    }

    bool pipe_test_interface::send_response(test_interface::response &res){
        
        // Write the data length.
        ssize_t written = write(m_fd_response, &res.data_length, sizeof(res.data_length));
        if (written == -1) {
            LOG_ERROR("Could not send the data length to the response pipe!");
            return false;
        }

        // Write the whole response at once.
        written = write(m_fd_response, res.data, res.data_length);
        if (written == -1) {
            LOG_ERROR("Could not send the data to the response pipe!");
            return false;
        }

        return true;
    }

    bool pipe_test_interface::receive_request(){

        // Data should look like this: length (4 bytes), Command (1 byte), data (? bytes)

        // Read the length. This is blocking until sizeof(length) bytes are there (or an error).
        size_t length = 0;
        ssize_t bytes_read = read(m_fd_request, &length, sizeof(length)); 
        if(bytes_read != sizeof(length)){
            LOG_ERROR("There was an error reading the length of the request from the request pipe.");  
            return false;
        }

        if(length < 1){
            LOG_ERROR("Message was too short for a valid request!");  
            return false;
        }

        // Clearing old data if exist.
        if(m_current_req.data != nullptr){
            free(m_current_req.data);
            m_current_req.data = nullptr;
        }

        // Creating new request.
        m_current_req = test_interface::request();
        m_current_req.data_length = length-1;

        bytes_read = read(m_fd_request, &m_current_req.cmd, sizeof(m_current_req.cmd)); 
        if(bytes_read != sizeof(m_current_req.cmd)){
            LOG_ERROR("There was an error reading the command of the request from the request pipe: %s.", strerror(errno));  
            return false;
        }

        // Receive data if data is expected.
        if(length > 1){
            // Allocating memory for data according to the length.
            m_current_req.data = (char*)malloc(m_current_req.data_length);

            // Receive data in a while loop to ensure that only partally receiving works.
            // This loop will terminate if there were 5 errors while receiving.
            int error_count = 0;
            size_t received_length = 0;
            while(received_length < m_current_req.data_length){
                
                // Read as much data as possible (up to the wanted length).
                bytes_read = read(m_fd_request, m_current_req.data+received_length, m_current_req.data_length-received_length);

                // Error handling
                if (bytes_read == -1) {
                    LOG_ERROR("There was an error reading the data of the request from the request pipe.");
                    error_count ++;
                } else if (bytes_read == 0) {
                    LOG_ERROR("Request pipe end of data reached, but not full data received (%d of %d).", (int)received_length, (int)m_current_req.data_length);
                    error_count ++;
                }else{
                    received_length += bytes_read;
                }

                if(error_count >= PIPE_READ_ERROR_MAX){
                    LOG_ERROR("Maximum of %d error reached while receiving data.", PIPE_READ_ERROR_MAX);
                    return false;
                }

            }
        }

        return true;
    }

    test_interface::request pipe_test_interface::get_request(){
        return m_current_req;
    }

};