all: my_dns

my_ping:my_dns.o
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

clean:
	rm -f *.o my_dns

