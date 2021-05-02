// Package vmess contains the implementation of VMess protocol and transportation.
//
// VMess contains both inbound and outbound connections. VMess inbound is usually used on servers
// together with 'freedom' to talk to final destination, while VMess outbound is usually used on
// clients with 'socks' for proxying.
package vmess

//go:generate go run github.com/v2fly/v2ray-core/v4/common/errors/errorgen

import (
	"time"

	"github.com/v2fly/v2ray-core/v4/common/platform"
)

var (
	AEADForced     bool
	AEADForced2022 bool
)

func init() {
	var defaultFlagValue = "NOT_DEFINED_AT_ALL"

	if time.Now().Year() >= 2022 {
		defaultFlagValue = "true_by_default_2022"
	}

	isAeadForced := platform.NewEnvFlag("v2ray.vmess.aead.forced").GetValue(func() string { return defaultFlagValue })
	if isAeadForced == "true" {
		AEADForced = true
	}

	if isAeadForced == "true_by_default_2022" {
		AEADForced = true
		AEADForced2022 = true
	}
}
