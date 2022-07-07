package shadowsocks

import (
	"io"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
)

var (
	ErrNotFound = newError("Not Found")
)

type Validator interface {
	Add(*protocol.MemoryUser) error
	Delete(string) error

	GetTCP(io.Reader) (*protocol.MemoryUser, io.Reader, error)
	GetUDP(*buf.Buffer) (*protocol.MemoryUser, *buf.Buffer, error)

	GetBehaviorSeed() uint64
}
