cmake_minimum_required(VERSION 3.10)

project(Stager C CXX)

# --- Options ---
option(BUILD_AS_EXE "Build stager as EXE (WinMain)" ON)
option(BUILD_AS_DLL "Build stager as DLL (experimental)" OFF)

# --- Toolchain Setup (if cross-compiling) ---
if(CMAKE_CROSSCOMPILING)
    message(STATUS "Cross-compiling Stager for Windows using toolchain: ${CMAKE_TOOLCHAIN_FILE}")
    # Toolchain file should set CMAKE_SYSTEM_NAME to Windows
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(FATAL_ERROR "Stager target system must be Windows. Set CMAKE_SYSTEM_NAME=Windows or use a Windows toolchain.")
endif()

# --- Compiler/Linker Flags (Windows) ---
set(WINDOWS_COMPILE_FLAGS "-Wall -Wextra -O2 -s") # -s strips symbols
set(WINDOWS_LINK_FLAGS "")

if(BUILD_AS_EXE)
    set(WINDOWS_LINK_FLAGS "${WINDOWS_LINK_FLAGS} -mwindows") # Link for GUI app (WinMain)
    # set(WINDOWS_LINK_FLAGS "${WINDOWS_LINK_FLAGS} -mconsole") # Link for console app (main)
else() # Build as DLL
    set(WINDOWS_LINK_FLAGS "${WINDOWS_LINK_FLAGS} -shared")
endif()

# No standard libs for stealth?
# set(WINDOWS_LINK_FLAGS "${WINDOWS_LINK_FLAGS} -nostdlib") # Careful with this

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WINDOWS_COMPILE_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${WINDOWS_COMPILE_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${WINDOWS_LINK_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${WINDOWS_LINK_FLAGS}")

# --- Source Files ---
add_library(stager_lib OBJECT stager.cpp)
# Optionally add ReflectiveLoader if embedding it directly into stager
# add_library(reflective_loader OBJECT ../../test_payloads/reflective_dll_test/ReflectiveLoader.c)

# --- Executable/DLL Target ---
if(BUILD_AS_EXE)
    add_executable(stager $<TARGET_OBJECTS:stager_lib>)
    set_target_properties(stager PROPERTIES OUTPUT_NAME "stager")
    target_link_libraries(stager PRIVATE kernel32 user32 wininet)
else() # Build as DLL
    add_library(stager SHARED $<TARGET_OBJECTS:stager_lib>)
    set_target_properties(stager PROPERTIES OUTPUT_NAME "stager_dll")
    target_link_libraries(stager PRIVATE kernel32 user32 wininet)
endif()

# --- Installation (Optional) ---
# install(TARGETS stager DESTINATION bin) # Example 