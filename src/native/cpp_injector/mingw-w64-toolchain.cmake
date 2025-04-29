# Sample CMake toolchain file for MinGW targeting Windows 64-bit

# Set the target system name
set(CMAKE_SYSTEM_NAME Windows)

# Specify the cross compilers
# Adjust paths if MinGW is installed elsewhere in the Docker image
set(CMAKE_C_COMPILER   /usr/bin/x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER /usr/bin/x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER  /usr/bin/x86_64-w64-mingw32-windres)

# Set the target architecture (optional, usually inferred by compiler name)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Where to look for target environment headers and libraries
# CMAKE_FIND_ROOT_PATH specifies the root directory for find_xxx() commands
# It usually points to the root of the target environment (MinGW installation)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)

# Adjust the default behavior of the FIND_XXX commands:
# Search programs in the host environment only.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# Search headers and libraries in the target environment only.
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY) 