cmake_minimum_required(VERSION 3.10) # Added minimum required version

# Project definition
project(AgentXNative C CXX)

# Add subdirectories for native modules
add_subdirectory(cpp_injector)

# Add out-of-source builds for stager and test payload
# Specify explicit binary directories relative to the main build directory
add_subdirectory(${CMAKE_SOURCE_DIR}/../../agent_implant/stager ${CMAKE_BINARY_DIR}/stager)
add_subdirectory(${CMAKE_SOURCE_DIR}/../../test_payloads/reflective_dll_test ${CMAKE_BINARY_DIR}/reflective_dll_test)

# Add other potential native components here
# add_subdirectory(persistence_module)
# add_subdirectory(network_scanner) 