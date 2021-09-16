#link
client_q_date:client_q_date.c server_snd_date
	gcc -g -Wall client_q_date.c -o  client_q_date -lsctp
server_snd_date:server_snd_date.c
	gcc -g -Wall server_snd_date.c -o server_snd_date -lsctp
clean:
	rm -f client_q_date server_snd_date
