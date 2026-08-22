// 平台无关的证书签名纯函数(从 certsource_windows.go 抽出, 供 Linux 单测与 Windows CNG 共用)。

package certsource

import (
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ecdsaRawToDER 把 P1363 raw R||S 签名转 Go 标准 DER 编码。
// part = 曲线字节数((bitSize+7)/8), 与 digest 长度无关 — P-384+SHA256 场景 digest=32 ≠ R=48。
func ecdsaRawToDER(raw []byte, bitSize int) ([]byte, error) {
	part := (bitSize + 7) / 8
	if len(raw) != 2*part {
		return nil, fmt.Errorf("unexpected ECDSA signature length %d (want %d)", len(raw), 2*part)
	}
	return asn1.Marshal(struct {
		R, S *big.Int
	}{R: new(big.Int).SetBytes(raw[:part]), S: new(big.Int).SetBytes(raw[part:])})
}

// pssSaltLength 计算 RSA-PSS 签名的 salt 长度:
// PSSSaltLengthEqualsHash → hash 大小; PSSSaltLengthAuto 不支持(需显式)。
func pssSaltLength(o *rsa.PSSOptions) (int, error) {
	salt := o.SaltLength
	switch salt {
	case rsa.PSSSaltLengthAuto:
		return 0, fmt.Errorf("rsa.PSSSaltLengthAuto is not supported")
	case rsa.PSSSaltLengthEqualsHash:
		salt = o.HashFunc().Size()
	}
	return salt, nil
}
