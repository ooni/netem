package netem

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/hkdf"
)

// https://www.rfc-editor.org/rfc/rfc9001.html#protection-keys
//
// computeHP derives the header protection key from the initial secret.
func computeHP(secret []byte) (hp []byte) {
	hp = hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic hp", 16)
	return
}

// SPDX-License-Identifier: BSD-3-Clause
// This code is borrowed from https://github.com/marten-seemann/qtls-go1-15
// https://github.com/marten-seemann/qtls-go1-15/blob/0d137e9e3594d8e9c864519eff97b323321e5e74/cipher_suites.go#L281
type aead interface {
	cipher.AEAD

	// explicitNonceLen returns the number of bytes of explicit nonce
	// included in each record. This is eight for older AEADs and
	// zero for modern ones.
	explicitNonceLen() int
}

// SPDX-License-Identifier: BSD-3-Clause
// This code is borrowed from https://github.com/marten-seemann/qtls-go1-15
// https://github.com/marten-seemann/qtls-go1-15/blob/0d137e9e3594d8e9c864519eff97b323321e5e74/cipher_suites.go#L375
func aeadAESGCMTLS13(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}
	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

// SPDX-License-Identifier: MIT
// This code is borrowed from https://github.com/lucas-clemente/quic-go/
// https://github.com/lucas-clemente/quic-go/blob/f3b098775e40f96486c0065204145ddc8675eb7c/internal/handshake/initial_aead.go#L60
// https://www.rfc-editor.org/rfc/rfc9001.html#protection-keys
//
// computeInitialKeyAndIV derives the packet protection key and Initialization Vector (IV) from the initial secret.
func computeInitialKeyAndIV(secret []byte) (key, iv []byte) {
	key = hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic key", 16)
	iv = hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic iv", 12)
	return
}

// SPDX-License-Identifier: MIT
// This code is borrowed from https://github.com/lucas-clemente/quic-go/
// https://github.com/lucas-clemente/quic-go/blob/f3b098775e40f96486c0065204145ddc8675eb7c/internal/handshake/initial_aead.go#L53
// https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
//
// computeSecrets computes the initial secrets based on the destination connection ID.
func computeSecrets(destConnID []byte) (clientSecret, serverSecret []byte) {
	initialSalt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, initialSalt)
	clientSecret = hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())
	serverSecret = hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "server in", crypto.SHA256.Size())
	return
}

// SPDX-License-Identifier: MIT
// This code is borrowed from https://github.com/lucas-clemente/quic-go/
// https://github.com/lucas-clemente/quic-go/blob/master/internal/handshake/hkdf.go
//
// hkdfExpandLabel HKDF expands a label.
func hkdfExpandLabel(hash crypto.Hash, secret, context []byte, label string, length int) []byte {
	b := make([]byte, 3, 3+6+len(label)+1+len(context))
	binary.BigEndian.PutUint16(b, uint16(length))
	b[2] = uint8(6 + len(label))
	b = append(b, []byte("tls13 ")...)
	b = append(b, []byte(label)...)
	b = b[:3+6+len(label)+1]
	b[3+6+len(label)] = uint8(len(context))
	b = append(b, context...)

	out := make([]byte, length)
	n, err := hkdf.Expand(hash.New, secret, b).Read(out)
	if err != nil || n != length {
		panic("quic: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

const aeadNonceLength = 12

// SPDX-License-Identifier: BSD-3-Clause
// This code is borrowed from https://github.com/marten-seemann/qtls-go1-15
// https://github.com/marten-seemann/qtls-go1-15/blob/0d137e9e3594d8e9c864519eff97b323321e5e74/cipher_suites.go#L319
//
// xorNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce before each call.
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	return result, err
}
