all:server client
server:server.o
	g++ -g -o server server.o
client:client.o
	g++ -g -o client client.o
server.o:server.c
	g++ -g -c server.c
client.o:client.c
	g++ -g -c client.c
clean:all
	rm all
