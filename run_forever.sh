cc server.c -lcrypto -o server
while true
do
	./server
	sleep 1
done
