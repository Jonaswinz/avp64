#ifndef FUZZING_TEST_INTERFACE_H
#define FUZZING_TEST_INTERFACE_H

#include <mqueue.h>
#include <string>
#include <algorithm>

#include "vcml/core/types.h"
#include "vcml/debugging/target.h"

#define LOG_INFO(fmt, ...) vcml::log_info("TEST_INTERFACE: " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) vcml::log_error("TEST_INTERFACE: " fmt, ##__VA_ARGS__)

#define REQUEST_LENGTH 256
#define RESPONSE_LENGTH 256

using std::string;

//TODO: rename to testing
namespace fuzzing{

    class test_interface{
        public: 

            enum command{
                CONTINUE, KILL, SET_BREAKPOINT, REMOVE_BREAKPOINT, SET_MMIO_TRACKING, DISABLE_MMIO_TRACKING, SET_MMIO_VALUE, SET_CODE_COVERAGE, REMOVE_CODE_COVERAGE, GET_CODE_COVERAGE, GET_EXIT_STATUS, RESET_CODE_COVERAGE, DO_RUN, WRITE_CODE_COVERAGE
            };

            struct request{
                command cmd;
                char* data = nullptr;
                size_t data_length = 0;
            };

            struct response{
                char* data = nullptr;
                size_t data_length = 0;
            };

            virtual ~test_interface() {}

            virtual bool send_response(response &req) = 0; 

            virtual bool receive_request() = 0;

            virtual request get_request() = 0;

    };

    class mq_test_interface: public test_interface{
        public:

            mq_test_interface();

            ~mq_test_interface();

            bool send_response(test_interface::response &req) override;

            bool receive_request() override;

            test_interface::request get_request() override;

        private:

            void clear_mq(const char* queue_name);

            const string mq_request_name = "/avp64-test-receiver";
            const string mq_response_name = "/avp64-test-sender";

            mq_attr m_attr;
            mqd_t m_mqt_requests, m_mqt_responses;
            char m_buffer[REQUEST_LENGTH];
            test_interface::request m_current_req;

    };

};

#endif