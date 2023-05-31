package netem

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/cryptobyte"
)

// ErrQUICParse is the error returned in case there is a QUIC parse error.
var ErrQUICParse = errors.New("quicparse: parse error")

// newErrQUICParse returns a new [ErrQUICParse].
func newErrQUICParse(message string) error {
	return fmt.Errorf("%w: %s", ErrQUICParse, message)
}

type longHeaderPacket interface {
	Decrypt(raw []byte) error
}

// clientInitial is a data structure to store the header fields and (decrypted) payload of a
// parsed QUIC Client Initial packet, as specified in https://www.rfc-editor.org/rfc/rfc9000.html#name-initial-packet.
type clientInitial struct {
	// FirstByte is the partly encrypted first byte of the Initial packet.
	// The lower 4 bits are protected by QUIC Header Protection.
	//  * Header Form (1),
	//  * Fixed Bit (1),
	//  * Long Packet Type (2),
	//  * Type-specific bits (4)
	FirstByte byte
	cursor    *bytes.Reader
	longHeaderPacket

	// QUICVersion is the QUIC version number.
	QUICVersion uint32

	// DestinationID is the variable length (up to 20 Byte) Destination Connection ID.
	DestinationID []byte

	// SourceID is the variable length (up to 20 Byte) Source Connection ID.
	SourceID []byte

	// Token is the QUIC token.
	Token []byte

	// Length is the total length of packet number and payload bytes.
	Length uint64

	// PnOffset is the offset for the packet number which prefixes the packet payload.
	PnOffset int

	// DecryptedPacketNumber is the decrypted packet number.
	// The packet number is expected to be 0 for the Client Initial.
	// Produced by clientInitial.Decrypt
	DecryptedPacketNumber []byte

	// Payload is the encrypted payload of the QUIC Client Initial.
	// Produced by clientInitial.Decrypt
	Payload []byte

	// DecryptedPayload is the decrypted payload of the packet.
	// Produced by clientInitial.Decrypt
	DecryptedPayload []byte
}

// UnmarshalLongHeaderPacket unmarshals a raw QUIC long header packet
// Return values:
// 1. the parsed clientInitial (on success)
// 2. the remaining data to be parsed [*bytes.Reader]
// 3. error (on failure)
func UnmarshalLongHeaderPacket(raw []byte) (longHeaderPacket, error) {
	// read the packet header byte
	cursor := bytes.NewReader(cryptobyte.String(raw))
	firstByte, err := cursor.ReadByte()
	if err != nil {
		return nil, newErrQUICParse("QUIC packet: cannot read first byte")
	}
	switch (firstByte & 0b1000_0000) >> 7 {
	case 1: // allow long header format

	default:
		return nil, newErrQUICParse("QUIC packet: unsupported header type")
	}

	// the packet type is encoded in bits 6 and 5 (MSB 8 7 6 5 4 3 2 1 LSB) of the first byte + 1
	ptype := (firstByte & 0x30) >> 4
	switch ptype {
	case 0: // Initial packet type
		ci := &clientInitial{
			FirstByte: firstByte,
			cursor:    cursor,
		}
		return ci, unmarshalInitial(raw, ci, cursor)
	default:
		return nil, newErrQUICParse("long header: unsupported packet type")
	}
}

// unmarshalInitial unmarshals a raw QUIC Client Initial packet
// Modifies the clientInitial instance, and the cursor [*bytes.Reader].
// Returns an error on failure.
func unmarshalInitial(raw []byte, ci *clientInitial, cursor *bytes.Reader) error {
	var err error
	// QUIC version (4)
	versionBytes := make([]byte, 4)
	if _, err = cursor.Read(versionBytes); err != nil {
		return newErrQUICParse("Initial header: cannot read version field")
	}
	ci.QUICVersion = binary.BigEndian.Uint32(versionBytes)
	switch ci.QUICVersion {
	case 0x1, 0xff00001d, 0xbabababa:
	// all good
	default:
		return newErrQUICParse("Initial header: unsupported QUIC version")
	}
	// Destination Connection ID (1 + n)
	var lendid uint8
	if lendid, err = cursor.ReadByte(); err != nil {
		return newErrQUICParse("Initial header: cannot read length destination ID")
	}
	ci.DestinationID = make([]byte, int(lendid))
	if _, err = cursor.Read(ci.DestinationID); err != nil {
		return newErrQUICParse("Initial header: cannot read destination ID")
	}
	// Source Connection ID (1 + n)
	var lensid uint8
	if lensid, err = cursor.ReadByte(); err != nil {
		return newErrQUICParse("Initial header: cannot read length source ID")
	}
	ci.SourceID = make([]byte, int(lensid))
	if _, err = cursor.Read(ci.SourceID); err != nil {
		return newErrQUICParse("Initial header: cannot read source ID")
	}
	// Token length (n)
	tokenlen, err := quicvarint.Read(cursor)
	if err != nil {
		return newErrQUICParse("Initial header: cannot read token length")
	}
	// Token (m)
	ci.Token = make([]byte, tokenlen)
	if _, err = cursor.Read(ci.Token); err != nil {
		return newErrQUICParse("Initial header: cannot read token")
	}
	// Length of the payload
	if ci.Length, err = quicvarint.Read(cursor); err != nil {
		return newErrQUICParse("Initial header: cannot read payload length")
	}
	// ci.Length = append([]byte{lengthfirstbyte}, ci.Length...)
	ci.PnOffset = int(cursor.Size()) - cursor.Len()
	return nil
}

// Decrypt decrypts the parsed Client Initial.
// Modifies the clientInitial instance.
// Returns an error on failure.
func (ci *clientInitial) Decrypt(raw []byte) error {
	// the 16-byte ciphertext sample used for header protection starts at pnOffset + 4
	sampleOffset := ci.PnOffset + 4
	sample := raw[sampleOffset : sampleOffset+16]

	// the AES header protection key is derived from the destination ID and a version-specific salt
	clientSecret, _ := computeSecrets(ci.DestinationID)
	hp := computeHP(clientSecret)
	block, err := aes.NewCipher(hp)
	if err != nil {
		return newErrQUICParse("decrypt Initial: error creating new AES cipher" + err.Error())
	}
	mask := make([]byte, block.BlockSize())
	if len(sample) != len(mask) {
		panic("invalid sample size")
	}
	// the mask used for header protection is obtained by encrypting the ciphertext sample
	block.Encrypt(mask, sample)

	// remove header protection (applied to the second half of the first byte)
	ci.FirstByte ^= mask[0] & 0xf

	// the packet number length is encoded in the two least significant bits of the first byte + 1
	pnlen := 1 << (ci.FirstByte & 0x03)
	ci.DecryptedPacketNumber = make([]byte, pnlen)
	if _, err = ci.cursor.Read(ci.DecryptedPacketNumber); err != nil {
		return newErrQUICParse("decrypt Initial: cannot read packet number")
	}
	// remove header protection from the packet number field
	for i, _ := range ci.DecryptedPacketNumber {
		ci.DecryptedPacketNumber[i] ^= mask[i+1]
		if ci.DecryptedPacketNumber[i] != 0 {
			return newErrQUICParse("decrypt Initial: unexpected packet number (expect 0)")
		}
	}
	// calculate the length of the payload
	payloadLength := int(ci.Length) - pnlen
	if payloadLength <= 0 {
		return newErrQUICParse("decrypt Initial: no payload")
	}
	// parse the payload
	ci.Payload = make([]byte, payloadLength)
	if _, err = ci.cursor.Read(ci.Payload); err != nil {
		return newErrQUICParse("decrypt Initial: cannot read payload")
	}
	// put together the decrypted header: first byte + rest (unprotected) + packet number
	// which is needed for payload decryption
	decryptedHeader := []byte{ci.FirstByte}
	decryptedHeader = append(decryptedHeader, raw[1:ci.PnOffset]...)
	decryptedHeader = append(decryptedHeader, ci.DecryptedPacketNumber...)

	// remove packet protection
	// the decryption requires the initial client secret, and the decrypted header as associated data
	ci.DecryptedPayload = decryptPayload(ci.Payload, clientSecret, decryptedHeader)
	return nil
}

// https://www.rfc-editor.org/rfc/rfc9001.html#name-packet-protection
//
// decryptPayload decrypts the payload of the packet by removing AEAD packet protection.
// AEAD decryption requires the initial client secret and associated data.
// Returns the decrypted payload.
func decryptPayload(payload, clientSecret []byte, ad []byte) []byte {
	// derive AEAD packet protection key and initialization vectors from the intial client secret
	key, iv := computeInitialKeyAndIV(clientSecret)
	cipher := aeadAESGCMTLS13(key, iv)

	nonceBuf := make([]byte, cipher.NonceSize())
	binary.BigEndian.PutUint64(nonceBuf[len(nonceBuf)-8:], uint64(0))

	// decrypt the payload
	decrypted, err := cipher.Open(nil, nonceBuf, payload, ad)
	if err != nil {
		panic(err)
	}
	return decrypted
}

// QUICFrame contains the content of a QUIC data frame.
// The payload of QUIC packets, after removing packet protection, consists of a sequence of complete frames.
type QUICFrame struct {
	// Type is the QUIC frame type, as defined in RFC9000
	Type int
	// Offset is the byte offset in the stream (stream-level sequence number)
	Offset uint64
	// Length is the length of the data payload
	Length uint64
	// Payload is the variable-length data payload
	Payload []byte
}

// nextFrame returns the next frame.
// Note that in a QUIC Client Initial there is usually only one frame (CRYPTO).
// It skips PADDING frames.
//
// Returns the next non-padding frame.
func nextFrame(cursor *bytes.Reader) (*QUICFrame, error) {
	// read the first byte indicating the frame type
	firstByte, err := cursor.ReadByte()
	if err != nil {
		return nil, newErrQUICParse("QUIC frame: cannot read first byte of frame")
	}
	for cursor.Len() > 0 {
		switch firstByte {
		// Skip PADDING frame
		case 0x00:
			var nextByte byte
			for nextByte == 0 {
				if nextByte, err = cursor.ReadByte(); err != nil {
					return nil, newErrQUICParse("QUIC frame: cannot read first byte of frame")
				}
			}
			continue
		// CRYPTO frame https://www.rfc-editor.org/rfc/rfc9000.html#name-crypto-frames
		case 0x06:
			// create a new frame
			crypto := &QUICFrame{
				Type: 0x06,
			}
			// the stream offset of the CRYPTO data
			if crypto.Offset, err = quicvarint.Read(cursor); err != nil {
				return nil, newErrQUICParse("CRYPTO frame: cannot read stream offset")
			}
			// the length of the data field in this CRYPTO frame
			if crypto.Length, err = quicvarint.Read(cursor); err != nil {
				return nil, newErrQUICParse("CRYPTO frame: cannot read data length")
			}
			// the cryptographic message data
			crypto.Payload = make([]byte, crypto.Length)
			if _, err = cursor.Read(crypto.Payload); err != nil {
				return nil, newErrQUICParse("CRYPTO frame: cannot read data")
			}
			return crypto, nil
		default:
			break
		}
	}
	return nil, newErrQUICParse("unsupported QUIC frame type")
}

// ExtractQUICServerName takes in input bytes read from the network, attempts
// to determine whether this is a QUIC Client Initial message,
// and, if affirmative, attempts to extract the server name.
func ExtractQUICServerName(rawInput []byte) (string, error) {
	if len(rawInput) <= 0 {
		return "", newErrTLSParse("no data")
	}
	// unmarshal the packet
	packet, err := UnmarshalLongHeaderPacket(rawInput)
	if err != nil {
		return "", err
	}
	// decrypt the initial packet
	err = packet.Decrypt(rawInput)
	if err != nil {
		return "", err
	}
	ci, ok := packet.(*clientInitial)
	if !ok {
		return "", newErrQUICParse("unexpected packet type")
	}
	// iterate through contained frames to find CRYPTO frame with SNI
	frame, err := nextFrame(bytes.NewReader(ci.DecryptedPayload))
	for frame != nil {
		if err != nil {
			return "", err
		}
		switch frame.Type {
		case 0x06:
			// unmarshaling a decrypted QUIC CRYPTO frame inside a Client Initial
			// packet is like unmarshaling a TLS Client Hello (TLS 1.3)
			hx, err := UnmarshalTLSHandshakeMsg(frame.Payload)
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
			return ret, err
		default:
			frame, err = nextFrame(bytes.NewReader(ci.DecryptedPayload))
			continue
		}
	}
	return "", newErrQUICParse("no CRYPTO frame")
}
