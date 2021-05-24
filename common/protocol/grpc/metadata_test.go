package grpc_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/metadata"

	"github.com/v2fly/v2ray-core/v4/common/net"
	. "github.com/v2fly/v2ray-core/v4/common/protocol/grpc"
)

func TestParseXRealIP(t *testing.T) {
	md := metadata.New(map[string]string{"X-Real-IP": "129.78.138.66"})
	addr := ParseXRealIP(md)
	if r := cmp.Diff(addr, net.ParseAddress("129.78.138.66")); r != "" {
		t.Error(r)
	}
}
