package shadowsocks

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"io"
	"sync"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/dice"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
)

type StreamValidator struct {
	sync.RWMutex

	user *protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool
}

func (v *StreamValidator) Add(user *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	v.user = user

	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(user.Account.(*MemoryAccount).Key)
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	return nil
}

func (v *StreamValidator) Delete(id string) error {
	v.Lock()
	defer v.Unlock()

	v.user = nil
	return nil
}

func (v *StreamValidator) GetTCP(reader io.Reader) (*protocol.MemoryUser, io.Reader, error) {
	v.RLock()
	defer v.RUnlock()

	if v.user == nil {
		return nil, nil, ErrNotFound
	}

	if account := v.user.Account.(*MemoryAccount); account.Cipher.IVSize() > 0 {
		iv := buf.New()
		if _, err := iv.ReadFullFrom(reader, account.Cipher.IVSize()); err != nil {
			return nil, nil, newError("failed to read IV").Base(err)
		}

		err := account.CheckIV(iv.Bytes())

		return v.user, io.MultiReader(iv, reader), err
	}

	return v.user, reader, nil
}

func (v *StreamValidator) GetUDP(payload *buf.Buffer) (*protocol.MemoryUser, *buf.Buffer, error) {
	v.RLock()
	defer v.RUnlock()

	if v.user == nil {
		return nil, nil, ErrNotFound
	}

	account := v.user.Account.(*MemoryAccount)

	var iv []byte
	if account.Cipher.IVSize() > 0 {
		// Keep track of IV as it gets removed from payload in DecodePacket.
		iv = make([]byte, account.Cipher.IVSize())
		copy(iv, payload.BytesTo(account.Cipher.IVSize()))
	}

	if err := account.Cipher.DecodePacket(account.Key, payload); err != nil {
		return nil, nil, newError("failed to decrypt UDP payload").Base(err)
	}

	if account.Cipher.IVSize() > 0 {
		if err := account.CheckIV(iv); err != nil {
			return v.user, payload, err
		}
	}

	return v.user, payload, nil
}

func (v *StreamValidator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}

func NewStreamValidator() Validator {
	return &StreamValidator{}
}
