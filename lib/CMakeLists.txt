add_library(dns dns.c udp.c mdns.c)

target_include_directories(dns
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
