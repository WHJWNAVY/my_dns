# my_dns
> DNS Query Code in C with Linux sockets

## Usage
```
Usage: ./my_dns [OPTION] <HOST> ...
Options:
	-h, --help			Show this help
	-t, --type <type>		Query type (A, AAAA)
	-s, --server <server>		DNS server address
	-4, --inet4			Query use IPv4
	-6, --inet6			Query use IPv6
Example:
	./my_dns baidu.com
	./my_dns -4 -t A baidu.com
```
## Example
```
$ make clean && make
$ ./my_dns -4 -t A baidu.com
Query:  baidu.com
Server: 223.5.5.5
Type:   A
Record: 2
        Name:    baidu.com
        Address: 110.242.68.66
        Name:    baidu.com
        Address: 39.156.66.10
```

## Reference
* [DNS Query Code in C with Linux sockets](https://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/)
* [GitHub - mDNS](https://github.com/mjansson/mdns)
