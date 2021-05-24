package grpc

import (
	"google.golang.org/grpc/metadata"

	"github.com/v2fly/v2ray-core/v4/common/net"
)

// ParseXRealIP parses X-Real-IP metadata in gRPC metadata, and return the IP in it.
func ParseXRealIP(md metadata.MD) net.Address {
	xri := md.Get("X-Real-IP")
	if len(xri) == 0 {
		return nil
	}
	return net.ParseAddress(xri[0])
}
