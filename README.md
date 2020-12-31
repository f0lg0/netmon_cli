# netmon_cli

A simple, lightweight, terminal packet sniffer written in C.

## DISCLAIMER

This tool was built for **EDUCATIONAL PURPOSES** only, I am not responsible for any damaged caused
by illcit use of this script.

## About 

As the header says, this is a dead simple packet sniffer written in C using ONLY built in libs. The
sniffer relies on raw sockets to capture incoming and outgoing packets from your **Linux** machine.

It has a REPL interface written from scratch and it can dump sniffed packets to a `txt` file. Maybe,
it will eventually support `pcap` files in the future.

I have developed this tool while studying the C language and Unix related programming so this is not
an advanced tool, it's more of a PoC for me but I have decided to share it anyway.

It's called `netmon` because it can be developed into a fully featured network monitoring tool, but
for now it's only a packet sniffer.

## Requirements

- Linux machine
- gcc compiler
- root permissions

## Features

- `showip [DOMAIN NAME]` --> shows the corresponding IPv4 and IPv6 address of a given domain name
- `sniff -p [NUMBER OF PACKETS] -f [TO FILE OR TO STDOUT]` --> sniff a given number of packets to a
file or to the screen (0 for `stdout`, 1 for log `file`)
