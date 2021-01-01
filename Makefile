netmon:
	$(CC) src/netmon.c src/repl.c src/info_gathering.c src/sniffer.c -o netmon.out

clean:
	rm netmon.out
	if [ -a log.txt ]; then rm log.txt; fi;