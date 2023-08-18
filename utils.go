package trace

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

func gernerateID() int {
	var processID = fmt.Sprintf("%015b", os.Getpid()&0x7f) //取进程ID的前15位

	var parity int
	id := processID
	for _, c := range id {
		if c == '1' {
			parity++
		}
	}
	if parity%2 == 0 {
		id += "1"
	} else {
		id += "0"
	}

	res, _ := strconv.ParseInt(id, 2, 64)
	return int(res)
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}
