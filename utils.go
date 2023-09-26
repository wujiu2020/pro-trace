package trace

import (
	"net"
)

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}
