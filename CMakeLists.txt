cmake_minimum_required(VERSION 3.16)

project (unstream)

add_executable(unstream src/unstream.c)

if (MSVC)
    set_property(TARGET unstream PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    add_compile_options(-O2 -Wall -Wextra -pedantic -Wno-strict-aliasing)
endif()

install(TARGETS unstream DESTINATION bin)
