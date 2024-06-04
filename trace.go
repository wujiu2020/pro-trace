package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
)

const defaultMaxHops = 30

type Tracer struct {
	// icmp packet id
	id int
	// icmp pachet listen
	icmpListen net.PacketConn
	// Timeout specifies a timeout before ping exits, regardless of how many
	// packets have been received.
	Timeout time.Duration
	// Count tells Tracer to stop after sending (and receiving) Count
	// packets in every hot. If this option is not specified, Tracer will operate until
	// interrupted.
	Count int
	// MaxHops is the max hop of trace
	MaxHops int
	// BeginHop is the begin hop of trace
	beginHop int
	// PacketInterval is the wait time between each packet send. Default is 1s.
	PacketInterval time.Duration
	// network is one of "ip", "ip4", or "ip6".
	network string
	// Size of packet being sent
	Size int
	// Source is the source IP address
	Source string
	// mtr
	Mtr bool

	addr       string
	ipaddr     net.IP
	done       chan interface{}
	lock       sync.Mutex
	ipv4       bool
	final      int
	finalCount int

	hops [][]*Hop
}

type Hop struct {
	SeqNum    int
	Address   net.Addr
	Hostname  string
	TTL       int
	RTT       time.Duration
	StartTime time.Time
	RetType   icmp.Type
	Error     error
}

// NewTracer returns a new Tracer and resolves the address.
func NewTracer(addr string) (*Tracer, error) {
	t := New(addr)
	return t, t.Resolve()
}

func New(addr string) *Tracer {
	return &Tracer{
		id:             0,
		Count:          3,
		PacketInterval: 10 * time.Millisecond,
		Size:           64,
		Timeout:        3 * time.Second,
		addr:           addr,
		ipv4:           false,
		network:        "ip",
		final:          -1,
		MaxHops:        defaultMaxHops,
		beginHop:       1,
		done:           make(chan interface{}),
	}
}

// Addr returns the string ip address of the target host.
func (t *Tracer) Addr() string {
	return t.addr
}

// Addr returns the string ip address of the target host.
func (t *Tracer) Hops() [][]*Hop {
	if t.final == -1 {
		return t.hops
	}
	return t.hops[:t.final]
}

func (t *Tracer) SetBeginHop(n int) error {
	if n < 1 && n > t.MaxHops {
		return errors.New("invalid begin hop")
	}
	return nil
}

// SetID sets the ICMP identifier.
func (t *Tracer) SetID(id int) {
	t.id = id
}

func (t *Tracer) Resolve() error {
	if len(t.addr) == 0 {
		return errors.New("addr cannot be empty")
	}
	ipaddr, err := net.ResolveIPAddr(t.network, t.addr)
	if err != nil {
		return err
	}

	t.ipv4 = isIPv4(ipaddr.IP)

	if t.ipv4 {
		t.network = "ip4:1"
	} else {
		t.network = "ip6:58"
	}

	t.ipaddr = ipaddr.IP

	return nil
}

func (t *Tracer) Stop() {
	t.lock.Lock()
	defer t.lock.Unlock()

	open := true
	select {
	case _, open = <-t.done:
	default:
	}

	if open {
		close(t.done)
	}
}

func (t *Tracer) Run() error {
	return t.RunWithContext(context.Background())
}

func (t *Tracer) RunWithContext(ctx context.Context) error {
	// listen addr
	if conn, err := net.ListenPacket(t.network, t.Source); err != nil {
		return err
	} else {
		t.icmpListen = conn
	}
	if err := t.icmpListen.SetReadDeadline(time.Now().Add(t.Timeout + time.Duration(t.MaxHops*t.Count)*t.PacketInterval)); err != nil {
		log.Fatal(err)
		return err
	}
	// init all hops
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.done:
		}
		return nil
	})

	g.Go(func() error {
		defer t.Stop()
		return t.listenICMP()
	})

	g.Go(func() error {
		return t.loopSend()
	})

	return g.Wait()
}

func (t *Tracer) listenICMP() error {
	timeout := time.NewTimer(t.Timeout + time.Duration(t.Count*t.MaxHops)*t.PacketInterval)
	for {
		select {
		case <-t.done:
			return nil
		case <-timeout.C:
			return nil
		default:
		}
		msg := make([]byte, 1500)
		n, peer, err := t.icmpListen.ReadFrom(msg)
		if err != nil {
			continue
		}
		if n == 0 {
			continue
		}
		proto := 1
		offset := 0
		if !t.ipv4 {
			offset = 20
			proto = 58
		}

		rm, err := icmp.ParseMessage(proto, msg[:net.FlagMulticast])
		if err != nil {
			log.Println(err)
			continue
		}
		var id, seq int
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			echoReply := rm.Body.(*icmp.Echo)
			id = echoReply.ID
			seq = echoReply.Seq
		case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
			id = int(binary.BigEndian.Uint16(msg[32+offset : 34+offset]))
			seq = int(binary.BigEndian.Uint16(msg[34+offset : 36+offset]))
		}
		if id != t.id {
			continue
		}
		hop := t.hops[seq/t.Count][seq%t.Count]
		hop.RTT = time.Since(hop.StartTime)
		hop.RetType = rm.Type
		hop.Address = peer
		hop.Error = nil
		if peer.String() == t.ipaddr.String() && (t.final == -1 || (seq/t.Count+1) == t.final) {
			if t.final == -1 {
				t.final = seq/t.Count + 1
			}
			t.finalCount += 1
			//当最后一跳的包接收完毕后等待一个设置的超时时间结束接收消息
			if t.finalCount == t.Count {
				t.done <- time.NewTimer(t.Timeout)
			}
		}
	}
}

func (t *Tracer) loopSend() error {
	interval := time.NewTicker(t.PacketInterval)
	ttl := t.beginHop
	count := 1
	t.addHops(ttl - 1)
	if err := t.sendICMP(ttl, count); err != nil {
		return err
	}
	timeout := time.NewTimer(t.Timeout + time.Duration(t.Count*t.MaxHops)*t.PacketInterval)
	for {
		select {
		case <-timeout.C:
			timeout.Stop()
			return nil
		case <-interval.C:
			if !t.Mtr {
				count += 1
				if count > t.Count {
					ttl += 1
					if ttl > t.MaxHops || (t.final != -1 && ttl > t.final) {
						interval.Stop()
						return nil
					}
					t.addHops(ttl - 1)
					count = 1
				}
				err := t.sendICMP(ttl, count)
				if err != nil {
					t.hops[ttl-1][count-1].Error = err
				}
			} else {
				if ttl > t.MaxHops || (t.final != -1 && ttl > t.final) {
					count += 1
					if count > t.Count {
						interval.Stop()
						return nil
					}
					ttl = 1
				}
				err := t.sendICMP(ttl, count)
				if err != nil {
					t.hops[ttl-1][count-1].Error = err
				}
				ttl += 1
				if len(t.Hops()) < ttl {
					t.addHops(ttl - 1)
				}
			}
		}
	}
}

func (t *Tracer) sendICMP(ttl, count int) error {
	var typ icmp.Type
	if t.ipv4 {
		typ = ipv4.ICMPTypeEcho
	} else {
		typ = ipv6.ICMPTypeEchoRequest
	}
	icmpHeader := icmp.Message{
		Type: typ,
		Code: 0,
		Body: &icmp.Echo{
			ID:   t.id,
			Data: bytes.Repeat([]byte{1}, t.Size),
			Seq:  (ttl-1)*t.Count + count - 1,
		},
	}
	ipv4.NewPacketConn(t.icmpListen).SetTTL(ttl)
	wb, err := icmpHeader.Marshal(nil)
	if err != nil {
		return err
	}
	t.hops[ttl-1][count-1].StartTime = time.Now()
	if _, err := t.icmpListen.WriteTo(wb, &net.IPAddr{IP: net.IP(t.ipaddr)}); err != nil {
		return err
	}
	return nil
}

func (t *Tracer) addHops(i int) {
	var hops []*Hop
	for j := 0; j < t.Count; j++ {
		hop := &Hop{
			TTL:    i + 1,
			Error:  errors.New("has no reply"),
			SeqNum: i*t.Count + j,
		}
		hops = append(hops, hop)
	}
	t.hops = append(t.hops, hops)
}
