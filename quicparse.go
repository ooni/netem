package netem

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

var parseError error = errors.New("error parsing QUIC Client Initial")

// QUICClientInitial is a data structure to store the header fields and (decrypted) payload
// of a QUIC Client Initial packet, as specified in https://www.rfc-editor.org/rfc/rfc9000.html#name-initial-packet.
// Do NOT create an empty QUICClientInitial.
type QUICClientInitial struct {
	// unmarshaled is an internal flag indicating that this QUICClientInitial was
	// constructed using NewQUICClientInitial, and is therefore unmarshaled.
	unmarshaled bool

	// FirstByte is the partly encrypted first byte of the Initial packet.
	// The lower 4 bits are protected by QUIC Header Protection.
	//  * Header Form (1),
	//  * Fixed Bit (1),
	//  * Long Packet Type (2),
	//  * Reserved Bits (2),
	//  * Packet Number Length (2)
	FirstByte byte

	// QUICVersion is the QUIC version number.
	QUICVersion uint32

	// DestinationID is the variable length (up to 20 Byte) Destination Connection ID.
	DestinationID []byte

	// SourceID is the variable length (up to 20 Byte) Source Connection ID.
	SourceID []byte

	// Token is the QUIC token.
	Token []byte

	// Length is the total length of packet number and payload bytes.
	Length []byte

	// PnOffset is the offset for the packet number which prefixes the packet payload.
	PnOffset int

	// DecryptedPacketNumber is the decrypted packet number.
	// The packet number is expected to be 0 for the Client Initial.
	DecryptedPacketNumber []byte

	// Payload is the encrypted payload of this QUIC Client Initial.
	Payload []byte

	// DecryptedHeader is the decrypted header containing the decrypted first byte,
	// and the decryped packet number.
	// The decrypted header is used for decrypting the payload.
	DecryptedHeader []byte

	// DecryptedPayload is the decrypted payload of the packet.
	// Produced by QUICClientInitial.Decrypt
	DecryptedPayload []byte
}

// NewQUICClientInitial constructs a QUICClientInitial by unmarshaling a raw QUIC Client Initial packet
func NewQUICClientInitial(raw []byte) (*QUICClientInitial, *stringWithCntr, error) {
	cursor := &stringWithCntr{cryptobyte.String(raw), 0}
	ci := &QUICClientInitial{}

	// first byte (1)
	if !cursor.readSingle(&ci.FirstByte) {
		return nil, cursor, parseError
	}
	// QUIC version (4)
	var versionBytes []byte
	if !cursor.read(&versionBytes, 4) {
		return nil, cursor, parseError
	}
	ci.QUICVersion = binary.BigEndian.Uint32(versionBytes)
	switch ci.QUICVersion {
	case 0x1, 0xff00001d, 0xbabababa:
	// all good
	default:
		return nil, cursor, parseError
	}

	// Destination Connection ID (1 + n)
	var lendid uint8
	if !cursor.readSingle(&lendid) {
		return nil, cursor, parseError
	}
	if !cursor.read(&ci.DestinationID, int(lendid)) {
		return nil, cursor, parseError
	}
	// Source Connection ID (1 + n)
	var lensid uint8
	if !cursor.readSingle(&lensid) {
		return nil, cursor, parseError
	}
	if !cursor.read(&ci.SourceID, int(lensid)) {
		return nil, cursor, parseError
	}

	// Token length (n)
	var tokenlenfirstbyte uint8
	if !cursor.readSingle(&tokenlenfirstbyte) {
		return nil, cursor, parseError
	}
	moreTokenlenBytes := getTwoBits(tokenlenfirstbyte, bit8, bit7)
	tokenlenfirstbyte &= 0b0011_1111 // mask out the length-indicating bits
	var tokenlen []byte
	if !cursor.read(&tokenlen, moreTokenlenBytes) {
		return nil, cursor, parseError
	}
	tokenlen = append([]byte{tokenlenfirstbyte}, tokenlen...)
	tokenlenInt := variableBytesToInt(tokenlen)
	// Token (m)
	if !cursor.read(&ci.Token, tokenlenInt) {
		return nil, cursor, parseError
	}

	// Length of the payload
	var lengthfirstbyte uint8
	if !cursor.readSingle(&lengthfirstbyte) {
		return nil, cursor, parseError
	}
	lenlength := getTwoBits(lengthfirstbyte, bit8, bit7)
	lengthfirstbyte &= 0b0011_1111 // mask out the length-indicating bits
	if !cursor.read(&ci.Length, lenlength) {
		return nil, cursor, parseError
	}
	ci.Length = append([]byte{lengthfirstbyte}, ci.Length...)
	ci.PnOffset = cursor.cntr
	ci.unmarshaled = true
	return ci, cursor, nil
}

// Decrypt decrypts the unmarshalled Client Initial.
// Only unmarshaled packets can be decrypted.
func (ci *QUICClientInitial) Decrypt(raw []byte, cursor *stringWithCntr) error {
	if !ci.unmarshaled {
		return errors.New("invalid decrypt operation: unmarshal (NewQUICClientInitial) before decrypt")
	}
	sampleOffset := ci.PnOffset + 4 // the offset for the ciphertext sample used for header protection
	sample := raw[sampleOffset : sampleOffset+16]
	clientSecret, _ := computeSecrets(ci.DestinationID)
	hp := computeHP(clientSecret)
	block, err := aes.NewCipher(hp)
	if err != nil {
		return errors.New("error creating new AES cipher" + err.Error())
	}
	mask := make([]byte, block.BlockSize())
	if len(sample) != len(mask) {
		panic("invalid sample size")
	}
	block.Encrypt(mask, sample)

	ci.FirstByte ^= mask[0] & 0xf
	pnlen := getTwoBits(ci.FirstByte, bit2, bit1) + 1

	if !cursor.read(&ci.DecryptedPacketNumber, pnlen) {
		return errors.New("cannot read packet number")
	}
	for i, _ := range ci.DecryptedPacketNumber {
		ci.DecryptedPacketNumber[i] ^= mask[i+1]
		if ci.DecryptedPacketNumber[i] != 0 {
			return errors.New("unexpected packet number for client initial (expect 0)")
		}
	}
	payloadLength := variableBytesToInt(ci.Length) - pnlen
	if payloadLength <= 0 {
		return errors.New("no payload")
	}
	if !cursor.read(&ci.Payload, payloadLength) {
		return errors.New("payload")
	}
	decryptedHeader := []byte{ci.FirstByte}
	decryptedHeader = append(decryptedHeader, raw[1:ci.PnOffset]...)
	decryptedHeader = append(decryptedHeader, ci.DecryptedPacketNumber...)
	ci.DecryptedPayload = decryptPayload(ci.Payload, ci.DestinationID, clientSecret, decryptedHeader)
	return nil
}

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

type QUICFrame struct {
	// Type is the QUIC frame type, as defined in RFC9000
	Type int

	// Length is the length of the data payload
	Length int

	// Payload is the variable-length data payload
	Payload []byte
}

// UnmarshalFrames separates the different QUIC frames contained in a QUIC packet.
// In a QUIC Client Initial there is usually only one frame, a CRYPTO frame.
func UnmarshalFrames(decrypted []byte) []*QUICFrame {
	var frames []*QUICFrame
	cursor := &stringWithCntr{cryptobyte.String(decrypted), 0}

	for !cursor.Empty() {
		var firstByte byte
		if !cursor.readSingle(&firstByte) {
			return frames
		}
		switch firstByte {
		case 0x00: // Skip padding
			var nextByte byte
			for nextByte == 0 {
				if !cursor.readSingle(&nextByte) {
					return frames
				}
			}
		// CRYPTO https://www.rfc-editor.org/rfc/rfc9000.html#name-crypto-frames
		case 0x06:
			crypto := &QUICFrame{
				Type: 0x06,
			}
			// the byte offset for the data in this CRYPTO frame
			var offsetFirstByte byte
			if !cursor.readSingle(&offsetFirstByte) {
				return frames
			}
			moreOffsetBytes := getTwoBits(offsetFirstByte, bit8, bit7)
			if !cursor.Skip(moreOffsetBytes) {
				return frames
			}
			// the length of the Crypto Data field in this CRYPTO frame
			var lenFirstByte byte
			if !cursor.readSingle(&lenFirstByte) {
				return frames
			}
			moreLenBytes := getTwoBits(lenFirstByte, bit8, bit7)
			lenFirstByte &= 0b0011_1111 // mask out the length-indicating bits
			var moreLen []byte
			if !cursor.read(&moreLen, moreLenBytes) {
				return frames
			}
			len := append([]byte{lenFirstByte}, moreLen...)
			lenInt := variableBytesToInt(len)
			crypto.Length = lenInt

			// the cryptographic message data
			if !cursor.read(&crypto.Payload, lenInt) {
				return frames
			}
			frames = append(frames, crypto)
		default:
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

// getTwoBits extracts two bits from a byte,
// returning the integer represented by these two bits
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

// converts byte slices of length <= 4 to int
func variableBytesToInt(b []byte) int {
	switch len(b) {
	case 1:
		return int(b[0])
	case 2:
		return int(binary.BigEndian.Uint16(b))
	case 3:
		return int(binary.BigEndian.Uint32(append([]byte{0}, b...)))
	case 4:
		return int(binary.BigEndian.Uint32(b))
	default:
		panic("can only handle <= 4 Bytes for int conversion")
	}
}

// ExtractQUICServerName takes in input bytes read from the network, attempts
// to determine whether this is a QUIC Client Initial message,
// and, if affirmative, attempts to extract the server name.
func ExtractQUICServerName(rawInput []byte) (string, error) {
	if len(rawInput) <= 0 {
		return "", newErrTLSParse("no data")
	}
	// unmarshal Client Initial
	clientInitial, cursor, err := NewQUICClientInitial(rawInput)
	if err != nil {
		return "", err
	}
	// decrypt Client.Initial
	clientInitial.Decrypt(rawInput, cursor)

	// unmarshal data frames
	frames := UnmarshalFrames(clientInitial.DecryptedPayload)
	for _, f := range frames {
		if f.Type == 0x06 {
			// unmarshaling a decrypted QUIC CRYPTO frame inside a Client Initial
			// packet is like unmarshaling a TLS Client Hello (TLS 1.3)
			hx, err := UnmarshalTLSHandshakeMsg(f.Payload)
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

// stringWithCntr is a cryptobyte.String with a counter of the raw bytes
type stringWithCntr struct {
	cryptobyte.String
	cntr int
}

// readSingle reads a single byte and increments the counter by 1
func (s *stringWithCntr) readSingle(out *byte) bool {
	var tmp []byte
	r := s.read(&tmp, 1)
	if r {
		*out = tmp[0]
	}
	return r
}

// read reads i bytes and increments the counter by i
func (s *stringWithCntr) read(out *[]byte, i int) bool {
	r := s.ReadBytes(out, i)
	if r {
		s.cntr += i
	}
	return r
}
