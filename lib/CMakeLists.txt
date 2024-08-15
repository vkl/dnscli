add_library(dns dns.c)

target_include_directories(dns
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
