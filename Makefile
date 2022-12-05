build:
	rm -f /home/ryanhemmila/testservice
	gcc -o /home/ryanhemmila/testservice main.c tls.c log.c config.c -I./include/ -lssl -lcrypto

install:
	systemctl stop testing
	rm -f /home/ryanhemmila/testservice
	gcc -o /home/ryanhemmila/testservice main.c tls.c log.c config.c -I./include/ -lssl -lcrypto
	systemctl start testing
	systemctl status testing
