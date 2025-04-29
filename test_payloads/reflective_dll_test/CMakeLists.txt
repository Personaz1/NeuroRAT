cmake_minimum_required(VERSION 3.10)

project(ReflectiveDLLTest C CXX)

# --- Toolchain Setup (if cross-compiling) ---
if(CMAKE_CROSSCOMPILING)
    message(STATUS "Cross-compiling Reflective DLL Test Payload using toolchain: ${CMAKE_TOOLCHAIN_FILE}")
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(FATAL_ERROR "Reflective DLL target system must be Windows.")
endif()

# --- Compiler/Linker Flags (Windows) ---
# Important flags for Reflective DLL:
# -fpic: Position Independent Code
# -nostdlib: Avoid linking standard libraries (loader handles necessary functions)
# -Wl,--no-seh: Disable SEH (optional, common for payloads)
# -s: Strip symbols
set(REFLECTIVE_COMPILE_FLAGS "-Wall -Wextra -O2 -fpic -s")
set(REFLECTIVE_LINK_FLAGS "-shared -nostdlib -Wl,--no-seh")
# Add other necessary libraries if payload_dll.cpp needs them beyond ReflectiveLoader
set(REFLECTIVE_LINK_LIBS "kernel32 user32") # For GetModuleHandle, GetProcAddress, MessageBoxW

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${REFLECTIVE_COMPILE_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${REFLECTIVE_COMPILE_FLAGS}")
# We build a SHARED library, but don't set CMAKE_SHARED_LINKER_FLAGS globally if it affects other targets

# --- Source Files ---
add_library(payload_dll_obj OBJECT payload_dll.cpp)
add_library(reflective_loader_obj OBJECT ReflectiveLoader.c)

# --- Target: Reflective DLL (output as .bin) ---
# Link the object files together into a shared library format first
add_library(payload_dll SHARED $<TARGET_OBJECTS:payload_dll_obj> $<TARGET_OBJECTS:reflective_loader_obj>)

# Apply specific linker flags for this target
target_link_options(payload_dll PRIVATE ${REFLECTIVE_LINK_FLAGS})
target_link_libraries(payload_dll PRIVATE ${REFLECTIVE_LINK_LIBS})

# Set the output name and extension
set_target_properties(payload_dll PROPERTIES 
    PREFIX "" 
    OUTPUT_NAME "payload" 
    SUFFIX ".bin"
)

# --- Installation (Optional) ---
install(TARGETS payload_dll DESTINATION bin) 