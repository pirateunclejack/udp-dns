package main

import (
	"fmt"
	dns_request "upd-dns/dns-request"
)

func main() {
	fmt.Println(dns_request.DigDomain("223.5.5.5:53", "www.baidu.com"))
}
