all:
	gcc -Wall -g -o binupdate -ldl -lpthread -lm binupdate.c pe.c

