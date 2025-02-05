#ifndef FUZZING_TEST_INTERFACE_H
#define FUZZING_TEST_INTERFACE_H

#include <mqueue.h>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <sys/ioctl.h>

#include "vcml/core/types.h"
#include "vcml/debugging/target.h"

#define LOG_INFO(fmt, ...) vcml::log_info("TEST_INTERFACE: " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) vcml::log_error("TEST_INTERFACE: " fmt, ##__VA_ARGS__)

#define MQ_REQUEST_LENGTH 256
#define MQ_RESPONSE_LENGTH 256

#define PIPE_READ_ERROR_MAX 5

using std::string;

//TODO: rename to testing
namespace testing{

    class test_interface{
        public: 

            enum interface{
                MQ, PIPE, INTERFACE_COUNT
            };

            enum command{
                CONTINUE, KILL, SET_BREAKPOINT, REMOVE_BREAKPOINT, SET_MMIO_TRACKING, DISABLE_MMIO_TRACKING, SET_MMIO_VALUE, SET_CODE_COVERAGE, REMOVE_CODE_COVERAGE, GET_CODE_COVERAGE, GET_EXIT_STATUS, RESET_CODE_COVERAGE, DO_RUN, DO_RUN_SHM, WRITE_CODE_COVERAGE
            };

            struct request{
                command cmd;
                char* data = nullptr;
                size_t data_length = 0;
            };

            //TODO success / failure code ?
            struct response{
                char* data = nullptr;
                size_t data_length = 0;
            };

            virtual ~test_interface() {}

            virtual bool start() = 0;

            virtual bool send_response(response &req) = 0; 

            virtual bool receive_request() = 0;

            virtual request get_request() = 0;

    };

    class mq_test_interface: public test_interface{
        public:

            mq_test_interface(string mq_request_name, string mq_response_name);

            ~mq_test_interface();

            bool start() override;

            bool send_response(test_interface::response &req) override;

            bool receive_request() override;

            test_interface::request get_request() override;

        private:

            void clear_mq(const char* queue_name);

            char* m_mq_request_name;
            char* m_mq_response_name;

            mq_attr m_attr;
            mqd_t m_mqt_requests, m_mqt_responses;
            char m_buffer[MQ_REQUEST_LENGTH];
            test_interface::request m_current_req;

    };

    class pipe_test_interface: public test_interface{
        public:

            pipe_test_interface(int fd_requests, int fd_response);

            ~pipe_test_interface();

            bool start() override;

            bool send_response(test_interface::response &req) override;

            bool receive_request() override;

            test_interface::request get_request() override;

        private:
            int m_fd_request;
            int m_fd_response;
            test_interface::request m_current_req;

    };

}  //namespace testing

#endif