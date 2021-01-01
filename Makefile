netmon:
	$(CC) netmon.c repl.c info_gathering.c sniffer.c -o netmon.out

clean:
	rm netmon.out
	if [ -a log.txt ]; then rm log.txt; fi;