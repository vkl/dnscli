add_library(dns dns.c udp.c mdns.c cli.c)

target_compile_definitions(dns PRIVATE)
target_include_directories(dns
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
