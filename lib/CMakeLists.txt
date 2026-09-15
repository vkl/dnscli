set(CURSES_NEED_NCURSES TRUE)
set(CURSES_NEED_WIDE TRUE)

find_package(Curses REQUIRED)

add_library(dns dns.c udp.c mdns.c cli.c)

target_link_libraries(dns PRIVATE ncurses)
target_compile_definitions(dns PRIVATE)
target_include_directories(dns
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
