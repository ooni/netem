package netem

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

type QUICClientInitial struct {
	// QUICVersion is the QUIC version number
	QUICVersion uint32

	QUICDestinationID []byte

	QUICSourceID []byte

	DecryptedPayload []byte
}

// UnmarshalQUICClientInitial is a super function that unmarshals and decrypts a QUIC Client Initial packet
// TODO(kelmenhorst): divide responsibilities over multiple functions
func UnmarshalQUICClientInitial(cursor cryptobyte.String) (*QUICClientInitial, error) {
	ci := &QUICClientInitial{}
	var hdr []byte

	// first byte (1)
	var firstByte []byte
	if !cursor.ReadBytes(&firstByte, 1) {
		return nil, errors.New("first byte")
	}
	hdr = append(hdr, firstByte...)

	// QUIC version (4)
	var versionBytes []byte
	if !cursor.ReadBytes(&versionBytes, 4) {
		return nil, errors.New("quic client initial: cannot read QUIC version field")
	}
	hdr = append(hdr, versionBytes...)
	ci.QUICVersion = binary.BigEndian.Uint32(versionBytes)

	switch ci.QUICVersion {
	case 0x1, 0xff00001d, 0xbabababa:
	// 	// all good
	default:
		return nil, errors.New("quic client initial: unknown protocol version")
	}

	// Destination Connection ID (1 + n)
	var lendid uint8
	if !cursor.ReadUint8(&lendid) {
		return nil, errors.New("quic client initial: cannot read destination connection ID")
	}
	if !cursor.ReadBytes(&ci.QUICDestinationID, int(lendid)) {
		return nil, errors.New("quic client initial: cannot read destination connection ID")
	}
	hdr = append(hdr, lendid)
	hdr = append(hdr, ci.QUICDestinationID...)

	// Source Connection ID (1 + n)
	var lensid uint8
	if !cursor.ReadUint8(&lensid) {
		return nil, errors.New("quic client initial: cannot read source connection ID")
	}
	if !cursor.ReadBytes(&ci.QUICSourceID, int(lensid)) {
		return nil, errors.New("quic client initial: cannot read source connection ID")
	}
	hdr = append(hdr, lensid)
	hdr = append(hdr, ci.QUICSourceID...)

	// Token length (n)
	var tokenlenfirstbyte uint8
	if !cursor.ReadUint8(&tokenlenfirstbyte) {
		return nil, errors.New("quic client initial: cannot read token length")
	}
	hdr = append(hdr, tokenlenfirstbyte)
	moreTokenlenBytes := getTwoBits(tokenlenfirstbyte, bit8, bit7)
	tokenlenfirstbyte &= 0b0011_1111 // mask out the length-indicating bits

	var tokenlen []byte
	if !cursor.ReadBytes(&tokenlen, moreTokenlenBytes) {
		return nil, errors.New("quic client initial: cannot read token length")
	}
	hdr = append(hdr, tokenlen...)
	tokenlen = append([]byte{tokenlenfirstbyte}, tokenlen...)
	tokenlenInt, _ := variableBytesToInt(tokenlen)

	// Token (m)
	var tmp []byte
	if !cursor.ReadBytes(&tmp, tokenlenInt) {
		return nil, errors.New("token")
	}
	hdr = append(hdr, tmp...)

	var lengthfirstbyte uint8
	if !cursor.ReadUint8(&lengthfirstbyte) {
		return nil, errors.New("length")
	}
	hdr = append(hdr, lengthfirstbyte)

	lenlength := getTwoBits(lengthfirstbyte, bit8, bit7)
	lengthfirstbyte &= 0b0011_1111 // mask out the length-indicating bits
	var payloadlen []byte
	if !cursor.ReadBytes(&payloadlen, lenlength) {
		return nil, errors.New("length")
	}
	hdr = append(hdr, payloadlen...)

	payloadlen = append([]byte{lengthfirstbyte}, payloadlen...)
	payloadlenInt, _ := variableBytesToInt(payloadlen)
	if payloadlenInt == 0 {
		return nil, errors.New("no payload")
	}

	var rest []byte
	if !cursor.ReadBytes(&rest, payloadlenInt) {
		return nil, errors.New("payload")
	}

	clientSecret, _ := computeSecrets(ci.QUICDestinationID)
	hp := computeHP(clientSecret)
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, errors.New("error creating new AES cipher" + err.Error())
	}

	// sample_offset := pn_offset + 4
	sample := rest[4:20]
	mask := make([]byte, block.BlockSize())
	if len(sample) != len(mask) {
		panic("invalid sample size")
	}
	block.Encrypt(mask, sample)

	hdr[0] ^= mask[0] & 0xf
	pnlen := getTwoBits(hdr[0], bit2, bit1) + 1

	for i := 0; i < pnlen; i++ {
		rest[i] ^= mask[i+1]
		if rest[i] != 0 {
			return nil, errors.New("unexpected packet number for client initial (expect 0)")
		}
		hdr = append(hdr, rest[i])
	}
	payload := rest[pnlen:]
	ci.DecryptedPayload = decryptPayload(payload, ci.QUICDestinationID, clientSecret, hdr)
	return ci, nil
}

type QUICFrame struct {
	frametype int
	len       int
	payload   []byte
}

func UnmarshalFrames(decrypted []byte) []*QUICFrame {
	var frames []*QUICFrame
	i := 0
	for i < len(decrypted) {
		firstByte := decrypted[i]
		switch firstByte {
		case 0x00:
			for decrypted[i] == 0 {
				i += 1
			}
		case 0x06:
			i += 1

			crypto := &QUICFrame{
				frametype: 0x06,
			}
			offsetFirstByte := decrypted[i]
			i += 1

			moreOffsetBytes := getTwoBits(offsetFirstByte, bit8, bit7)
			i += moreOffsetBytes

			lenFirstByte := decrypted[i]
			i += 1
			moreLenBytes := getTwoBits(lenFirstByte, bit8, bit7)
			lenFirstByte &= 0b0011_1111 // mask out the length-indicating bits

			len := []byte{lenFirstByte}
			len = append(len, decrypted[i:i+moreLenBytes]...)
			lenInt, _ := variableBytesToInt(len)
			crypto.len = lenInt

			i += moreLenBytes
			crypto.payload = decrypted[i : i+lenInt]
			frames = append(frames, crypto)
			i += lenInt
		default:
			i += 1
		}
	}
	return frames
}

const (
	bit8 byte = 0b1000_0000
	bit7 byte = 0b0100_0000
	bit6 byte = 0b0010_0000
	bit5 byte = 0b0001_0000
	bit4 byte = 0b0000_1000
	bit3 byte = 0b0000_0100
	bit2 byte = 0b0000_0010
	bit1 byte = 0b0000_0001
)

func getTwoBits(b, msb, lsb byte) int {
	r := 0
	if b&msb > 0 {
		r += 2
	}
	if b&lsb > 0 {
		r += 1
	}
	return r
}

func variableBytesToInt(b []byte) (int, error) {
	switch len(b) {
	case 1:
		return int(b[0]), nil
	case 2:
		return int(binary.BigEndian.Uint16(b)), nil
	case 3:
		return int(binary.BigEndian.Uint32(append([]byte{0}, b...))), nil
	case 4:
		return int(binary.BigEndian.Uint32(b)), nil
	default:
		return 0, errors.New("can only handle <= 4 Bytes for int conversion")
	}
}

// https://www.rfc-editor.org/rfc/rfc9001.html#protection-keys
//
// computeHP derives the header protection key from the initial secret.
func computeHP(secret []byte) (hp []byte) {
	hp = hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic hp", 16)
	return
}

// ExtractQUICServerName takes in input bytes read from the network, attempts
// to determine whether this is a QUIC Client Initial message,
// and, if affirmative, attempts to extract the server name.a ClientHello
func ExtractQUICServerName(rawInput []byte) (string, error) {
	if len(rawInput) <= 0 {
		return "", newErrTLSParse("no data")
	}
	clientInitial, err := UnmarshalQUICClientInitial(cryptobyte.String(rawInput))
	if err != nil {
		return "", err
	}
	frames := UnmarshalFrames(clientInitial.DecryptedPayload)
	for _, f := range frames {
		if f.frametype == 0x06 {
			hx, err := UnmarshalTLSHandshakeMsg(f.payload)
			if err != nil {
				return "", err
			}
			if hx.ClientHello == nil {
				return "", newErrTLSParse("no client hello")
			}
			exts, err := UnmarshalTLSExtensions(hx.ClientHello.Extensions)
			if err != nil {
				return "", err
			}
			snext, found := FindTLSServerNameExtension(exts)
			if !found {
				return "", newErrTLSParse("no server name extension")
			}
			ret, err := UnmarshalTLSServerNameExtension(snext.Data)
			fmt.Println("SNI: -------", ret)
			return ret, err
		}
	}
	return "", newErrTLSParse("no CRYPTO frame")
}

var (
	quicSaltOld = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSaltV1  = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2  = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

const (
	hkdfLabelKeyV1 = "quic key"
	hkdfLabelKeyV2 = "quicv2 key"
	hkdfLabelIVV1  = "quic iv"
	hkdfLabelIVV2  = "quicv2 iv"
)

// https://www.rfc-editor.org/rfc/rfc9001.html#name-packet-protection
//
// decryptPayload decrypts the payload of the packet.
func decryptPayload(payload, destConnID []byte, clientSecret []byte, ad []byte) []byte {
	myKey, myIV := computeInitialKeyAndIV(clientSecret)
	cipher := aeadAESGCMTLS13(myKey, myIV)

	nonceBuf := make([]byte, cipher.NonceSize())
	binary.BigEndian.PutUint64(nonceBuf[len(nonceBuf)-8:], uint64(0))
	decrypted, err := cipher.Open(nil, nonceBuf, payload, ad)
	if err != nil {
		panic(err)
	}
	return decrypted
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

const (
	aeadNonceLength   = 12
	noncePrefixLength = 4
)

// SPDX-License-Identifier: BSD-3-Clause
// This code is borrowed from https://github.com/marten-seemann/qtls-go1-15
// https://github.com/marten-seemann/qtls-go1-15/blob/0d137e9e3594d8e9c864519eff97b323321e5e74/cipher_suites.go#L319
//
// xoredNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce before each call.
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
