bindir = /usr/bin

CFLAGS = --std=c99

hellomake: eigrp_main.c eigrp_base.c eigrp_ip4.c eigrp_ip6.c utils.c vector.c linkedlist.c eigrp_prot.c hashtable.c packet_factory.c collection.c netlink.c telnet.c libnetlink.c libtelnet.c config_controller.c
	gcc -pthread -g eigrp_main.c eigrp_base.c eigrp_ip4.c eigrp_ip6.c utils.c vector.c linkedlist.c eigrp_prot.c hashtable.c packet_factory.c collection.c netlink.c telnet.c libnetlink.c libtelnet.c config_controller.c -o eigrp -lcrypt

install: eigrp
	install eigrp $(DESTDIR)$(bindir)

clean:
	-rm -f eigrp
