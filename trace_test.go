package trace_test

import (
	"fmt"
	"testing"
	trace "github.com/wujiu2020/pro-trace"
)

func TestTrace(t *testing.T) {
	tracer, err := trace.NewTracer("www.jd.com")
	if err != nil {
		fmt.Println(err)
	}
	if err := tracer.Run(); err != nil {
		fmt.Println(err)
	}
	for _, hops := range tracer.Hops() {
		for _, hop := range hops {
			fmt.Printf("%+v", hop)
		}
	}
}
