AM_CFLAGS = -I..
AM_LDFLAGS = -L..

ipaccess_telnet_SOURCES = telnet-client.c ../libtelnet.h ipaccess-auth.c
ipaccess_telnet_LDADD = ../libtelnet.la -lssl
ipaccess_telnet_CFLAGS = -DNANO_BTS_CLI_CLIENT

telnet_client_SOURCES = telnet-client.c ../libtelnet.h
telnet_client_LDADD = ../libtelnet.la

telnet_chatd_SOURCES = telnet-chatd.c ../libtelnet.h
telnet_chatd_LDADD = ../libtelnet.la

telnet_proxy_SOURCES = telnet-proxy.c ../libtelnet.h
telnet_proxy_LDADD = ../libtelnet.la

bin_PROGRAMS = telnet-client telnet-chatd telnet-proxy ipaccess-telnet
