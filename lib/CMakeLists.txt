add_library(dns dns.c udp.c mdns.c cli.c)

add_definitions(-DDEBUG_TRACE)

target_include_directories(dns
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
