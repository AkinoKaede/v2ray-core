package shadowsocks

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"io"
	"strings"
	"sync"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/dice"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
)

type AEADValidator struct {
	sync.RWMutex
	users []*protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool
}

const (
	MaxNonceSize = 12
)

var (
	FirstBytesLength int32 = 32 + 2 + 16
	ZeroNonce        [MaxNonceSize]byte
)

func (v *AEADValidator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() && len(v.users) > 0 {
		return newError("The cipher is not support multi-user")
	}
	v.users = append(v.users, u)

	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	return nil
}

func (v *AEADValidator) Delete(email string) error {
	if email == "" {
		return newError("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	idx := -1
	for i, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			break
		}
	}

	if idx == -1 {
		return newError("User ", email, " not found.")
	}
	ulen := len(v.users)

	v.users[idx] = v.users[ulen-1]
	v.users[ulen-1] = nil
	v.users = v.users[:ulen-1]

	return nil
}

func (v *AEADValidator) GetTCP(reader io.Reader) (*protocol.MemoryUser, io.Reader, error) {
	v.RLock()
	defer v.RUnlock()

	firstBytes := buf.New()
	if _, err := firstBytes.ReadFullFrom(reader, FirstBytesLength); err != nil {
		return nil, nil, newError("failed to read first bytes").Base(err)
	}

	for _, user := range v.users {
		account := user.Account.(*MemoryAccount)
		accountCipher := account.Cipher.(*AEADCipher)
		subkey := make([]byte, accountCipher.KeySize())
		hkdfSHA1(account.Key, firstBytes.BytesTo(accountCipher.IVSize()), subkey)
		cipher := accountCipher.AEADAuthCreator(subkey)
		if _, err := cipher.Open(nil, ZeroNonce[:cipher.NonceSize()],
			firstBytes.BytesRange(accountCipher.IVSize(), accountCipher.IVSize()+2+16), nil); err == nil {
			err := account.CheckIV(firstBytes.BytesTo(accountCipher.IVSize()))

			return user, io.MultiReader(firstBytes, reader), err
		}
	}

	return nil, io.MultiReader(firstBytes, reader), ErrNotFound
}

func (v *AEADValidator) GetUDP(payload *buf.Buffer) (*protocol.MemoryUser, *buf.Buffer, error) {
	v.RLock()
	defer v.RUnlock()

	defer payload.Release()

	for _, user := range v.users {
		account := user.Account.(*MemoryAccount)

		cipher := account.Cipher.(*AEADCipher)
		buffer := buf.FromBytes(payload.Bytes())

		if err := account.Cipher.DecodePacket(account.Key, buffer); err == nil {
			err := account.CheckIV(payload.BytesTo(cipher.IVSize()))

			return user, buffer, err
		}

		defer buffer.Release()
	}

	return nil, nil, ErrNotFound
}

func (v *AEADValidator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}

func NewAEADValidator() Validator {
	return &AEADValidator{}
}
