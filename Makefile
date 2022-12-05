build:
	systemctl stop testing
	rm -f /home/ryanhemmila/testservice
	gcc -o /home/ryanhemmila/testservice main.c -lssl -lcrypto
	systemctl start testing
	systemctl status testing
