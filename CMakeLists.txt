##############################################################################
#                                                                            #
# Copyright 2024 Lukas Jünger, Nils Bosbach                                  #
#                                                                            #
# This software is licensed under the MIT license.                           #
# A copy of the license can be found in the LICENSE file at the root         #
# of the source tree.                                                        #
#                                                                            #
##############################################################################

cmake_minimum_required(VERSION 3.12)
project(avp64 VERSION 2024.08.02 LANGUAGES C CXX)

option(AVP64_BUILD_TESTS "Build unit tests" OFF)
option(AVP64_BUILD_RUNNER "Build avp64 runner" ON)
set(AVP64_LINTER "" CACHE STRING "Code linter to use")

include(cmake/common.cmake)
find_github_repo(vcml "machineware-gmbh/vcml")

set(OCX_QEMU_ARM_BUILD_TESTS OFF CACHE BOOL "disable ocx tests")
find_github_repo(ocx-qemu-arm "snps-virtualprototyping/ocx-qemu-arm")

set(src "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(inc "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(gen ${CMAKE_CURRENT_BINARY_DIR}/gen)

configure_file(${src}/avp64/version.h.in
               ${gen}/avp64/version.h @ONLY)

set(sources
    ${src}/avp64/core.cpp
    ${src}/avp64/cpu.cpp
    ${src}/fuzzing/test_server.cpp
    ${src}/fuzzing/probe.cpp
    ${src}/fuzzing/can_injector.cpp
    ${src}/fuzzing/test.grpc.pb.cc
    ${src}/fuzzing/test.pb.cc
)

add_library(avp64 STATIC ${sources})

#Fuzzing
## If GLIBCXX_3.4.29 error: export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/net/sw/gcc/gcc-11.4.1/lib64 (or similar, depends on system path)
## And run build command after this in command line
set(gRPC_BUILD_GRPC_CSHARP_PLUGIN OFF CACHE BOOL "")
set(gRPC_BUILD_GRPC_NODE_PLUGIN OFF CACHE BOOL "")
set(gRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN OFF CACHE BOOL "")
set(gRPC_BUILD_GRPC_PHP_PLUGIN OFF CACHE BOOL "")
set(gRPC_BUILD_GRPC_PYTHON_PLUGIN OFF CACHE BOOL "")
set(gRPC_BUILD_GRPC_RUBY_PLUGIN OFF CACHE BOOL "")
set(gRPC_BUILD_GRPCPP_OTEL_PLUGIN OFF CACHE BOOL "")
set(ABSL_ENABLE_INSTALL ON)
find_github_repo(grpc "grpc/grpc" "v1.62.0")
target_link_libraries(avp64 PUBLIC grpc++_reflection grpc++ protobuf::libprotobuf)


target_compile_options(avp64 PRIVATE ${MWR_COMPILER_WARN_FLAGS})
target_include_directories(avp64 PUBLIC ${inc})
target_include_directories(avp64 PUBLIC ${gen})
target_include_directories(avp64 PUBLIC ${OCX_QEMU_ARM_HOME}/ocx/include)
target_link_libraries(avp64 PUBLIC ${CMAKE_DL_LIBS})
target_link_libraries(avp64 PUBLIC vcml)
set_target_properties(avp64 PROPERTIES CXX_STANDARD 17)
set_target_properties(avp64 PROPERTIES CXX_CLANG_TIDY "${AVP64_LINTER}")
set_target_properties(avp64 PROPERTIES VERSION "${AVP64_VERSION}")
set_target_properties(avp64 PROPERTIES SOVERSION "${AVP64_VERSION_MAJOR}")

if(NOT ${AVP64_LINTER} STREQUAL "")
    # -std=c++17 is not passed to the compiler if it is the comiler's default
    # this caused problems with clang-tidy
    set_target_properties(avp64 PROPERTIES CXX_STANDARD_REQUIRED ON)
endif()

set_target_properties(ocx-qemu-arm PROPERTIES EXCLUDE_FROM_ALL FALSE)

install(TARGETS avp64)
install(TARGETS ocx-qemu-arm DESTINATION lib)
install(DIRECTORY sw/ DESTINATION sw)
install(DIRECTORY ${inc}/ DESTINATION include)
install(DIRECTORY ${gen}/ DESTINATION include)

if(AVP64_BUILD_TESTS)
    message(STATUS "Building AVP64 tests")
    enable_testing()
    add_subdirectory(tests)
endif()

if(AVP64_BUILD_RUNNER)
    add_executable(avp64-runner
        ${src}/avp64/system.cpp
        ${src}/avp64/main.cpp
    )

    target_compile_options(avp64-runner PRIVATE ${MWR_COMPILER_WARN_FLAGS})
    target_include_directories(avp64-runner PRIVATE ${src})
    set_target_properties(avp64-runner PROPERTIES CXX_STANDARD 17)
    set_target_properties(avp64-runner PROPERTIES CXX_CLANG_TIDY "${AVP64_LINTER}")
    set_target_properties(avp64-runner PROPERTIES VERSION "${AVP64_VERSION}")
    set_target_properties(avp64-runner PROPERTIES SOVERSION "${AVP64_VERSION_MAJOR}")
    target_link_whole_archives(avp64-runner avp64)
    target_link_whole_archives(avp64-runner vcml)

    if(NOT ${AVP64_LINTER} STREQUAL "")
        # -std=c++17 is not passed to the compiler if it is the comiler's default
        # this caused problems with clang-tidy
        set_target_properties(avp64-runner PROPERTIES CXX_STANDARD_REQUIRED ON)
    endif()

    install(TARGETS avp64-runner)
endif()
