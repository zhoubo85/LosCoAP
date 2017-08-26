allobjs = main.o loscoap_core.o loscoap_os_unix.o

coap_client : $(allobjs)
	cc -o coap_client $(allobjs) -g

main.o : ./test/main.c ./include/coap_core.h ./include/los_coap.h 
	cc -c ./test/main.c -g

loscoap_core.o : ./src/loscoap_core.c ./include/coap_core.h ./include/los_coap.h ./include/los_unix.h 
	cc -c ./src/loscoap_core.c -g

loscoap_os_unix.o : ./src/loscoap_os_unix.c ./include/coap_core.h ./include/los_coap.h ./include/los_unix.h 
	cc -c ./src/loscoap_os_unix.c -g
	
clean :
	rm coap_client $(allobjs)