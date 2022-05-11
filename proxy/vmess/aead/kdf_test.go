package aead

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKDFValue(t *testing.T) {
	GeneratedKey := KDF([]byte("Demo Key for KDF Value Test"), "Demo Path for KDF Value Test", "Demo Path for KDF Value Test2", "Demo Path for KDF Value Test3")
	fmt.Println(hex.EncodeToString(GeneratedKey))
	assert.Equal(t, "c9847c69054b84e0446bc3118d84d5b12f34bd5141ccd463bf1119a517ce18dc", hex.EncodeToString(GeneratedKey), "Should generate expected KDF Value")
}
