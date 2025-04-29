cmake_minimum_required(VERSION 3.10)
project(cpp_injector CXX)

# Устанавливаем, что собираем под Windows
set(CMAKE_SYSTEM_NAME Windows)

# Устанавливаем кросс-компиляторы MinGW (если необходимо)
# Пути могут отличаться в зависимости от установки MinGW в Docker-образе
# Пример для Debian/Ubuntu:
# set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc)
# set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
# set(CMAKE_RC_COMPILER  x86_64-w64-mingw32-windres)

# Указываем C++ стандарт
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Добавляем исходные файлы - используем MODULE для DLL под MinGW
add_library(cpp_injector MODULE 
    injector.cpp 
    injector.h
)

# Добавляем флаги для статической линковки стандартных библиотек
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -static-libgcc -static-libstdc++")

# Линкуем необходимые Windows библиотеки
target_link_libraries(cpp_injector PRIVATE kernel32 ntdll user32)

# Указываем папку для вывода артефактов (DLL)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Добавляем include директорию
target_include_directories(cpp_injector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

message(STATUS "Configuring cpp_injector for Windows") 