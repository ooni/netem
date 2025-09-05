package netem

//
// References:
//
// - https://datatracker.ietf.org/doc/html/rfc8446
//
// - https://datatracker.ietf.org/doc/html/rfc6066
//
// - https://pkg.go.dev/golang.org/x/crypto/cryptobyte
//
// - https://tls13.xargs.org/#client-hello
//

import (
	"crypto/tls"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// ErrTLSParse is the error returned in case there is a TLS parse error.
var ErrTLSParse = errors.New("tlsparse: parse error")

// newErrTLSParse returns a new [ErrParse].
func newErrTLSParse(message string) error {
	return fmt.Errorf("%w: %s", ErrTLSParse, message)
}

// TLSRecordHeader is a TLS TLSRecordHeader.
type TLSRecordHeader struct {
	// ContentType is the type of the content.
	ContentType uint8

	// ProtocolVersion is the version of the TLS protocol.
	ProtocolVersion uint16

	// Length is the length of tls packet
	Length uint16

	// Rest contains the rest of the message.
	Rest []byte
}

// UnmarshalTLSRecordHeader unmarshals a RecordHeader.
//
// Return value:
//
// 1. the parsed RecordHeader (on success);
//
// 2. the unparsed bytes (on success), which may be empty if the
// input only contained a whole RecordHeader;
//
// 3. an error (nil on success).
func UnmarshalTLSRecordHeader(cursor cryptobyte.String) (*TLSRecordHeader, cryptobyte.String, error) {
	rh := &TLSRecordHeader{}

	if !cursor.ReadUint8(&rh.ContentType) {
		return nil, nil, newErrTLSParse("record header: cannot read content type field")
	}

	if !cursor.ReadUint16(&rh.ProtocolVersion) {
		return nil, nil, newErrTLSParse("record header: cannot read protocol version field")
	}

	if !cursor.ReadUint16(&rh.Length) {
		return nil, nil, newErrTLSParse("record header: cannot read protocol version field")
	}

	if !cursor.ReadBytes(&rh.Rest, min(int(rh.Length), len(cursor))) {
		return nil, nil, newErrTLSParse("record header: cannot read the rest of the message")
	}

	switch rh.ProtocolVersion {
	case tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13:
		// all good
	default:
		return nil, nil, newErrTLSParse("record header: unknown protocol version")
	}

	//
	// RFC 8446 defines the following content types:
	//
	//	enum {
	//		invalid(0),
	//		change_cipher_spec(20),
	//		alert(21),
	//		handshake(22),
	//		application_data(23),
	//		(255)
	//	} ContentType;
	//
	// See https://datatracker.ietf.org/doc/html/rfc8446#section-5
	//
	switch rh.ContentType {
	case 20, 21, 22, 23:
		// all good
	default:
		return nil, nil, newErrTLSParse("record header: unknown content type")
	}

	return rh, cursor, nil
}

// TLSHandshakeMsg is the TLSHandshakeMsg message.
type TLSHandshakeMsg struct {
	// HandshakeType is the type of handshake message.
	HandshakeType uint8

	// ClientHello is either nil or the parsed ClientHello.
	ClientHello *TLSClientHello
}

// UnmarshalTLSHandshakeMsg unmarshals an Handshake message.
//
// Return value:
//
// 1. the parsed Handshake (on success);
//
// 2. an error (nil on success).
func UnmarshalTLSHandshakeMsg(cursor cryptobyte.String) (*TLSHandshakeMsg, error) {
	h := &TLSHandshakeMsg{}

	if !cursor.ReadUint8(&h.HandshakeType) {
		return nil, newErrTLSParse("handshake: cannot read type field")
	}

	var rest cryptobyte.String
	if !cursor.ReadUint24LengthPrefixed(&rest) {
		return nil, newErrTLSParse("handshake: cannot read the rest of the message")
	}

	//
	// RFC 8446 defines the follwing handshake types:
	//
	//	enum {
	//		client_hello(1),
	//		server_hello(2),
	//		new_session_ticket(4),
	//		end_of_early_data(5),
	//		encrypted_extensions(8),
	//		certificate(11),
	//		certificate_request(13),
	//		certificate_verify(15),
	//		finished(20),
	//		key_update(24),
	//		message_hash(254),
	//		(255)
	//	} HandshakeType;
	//
	// See https://datatracker.ietf.org/doc/html/rfc8446#section-4
	//
	switch h.HandshakeType {
	case 1: // client_hello
		clientHello, err := unmarshalTLSClientHello(rest)
		if err != nil {
			return nil, err
		}
		h.ClientHello = clientHello
		return h, nil

	default:
		return nil, newErrTLSParse("handshake: unsupported type")
	}
}

// TLSClientHello is the TLSClientHello message.
type TLSClientHello struct {
	// ProtocolVersion is the protocol version.
	ProtocolVersion uint16

	// Random contains exacty 32 bytes of random data.
	Random []byte

	// LegacySessionID is the legacy session ID.
	LegacySessionID cryptobyte.String

	// CipherSuites contains the client cipher suites.
	CipherSuites cryptobyte.String

	// LegacyCompressionMethods contains the legacy compression methods.
	LegacyCompressionMethods cryptobyte.String

	// Extensions contains the extensions.
	Extensions cryptobyte.String
}

// unmarshalTLSClientHello unmarshals a ClientHello message.
//
// Return value:
//
// 1. the parsed ClientHello (on success);
//
// 2. an error (nil on success).
func unmarshalTLSClientHello(cursor cryptobyte.String) (*TLSClientHello, error) {
	ch := &TLSClientHello{}

	//
	// RFC 8446 defines the ClientHello as follows:
	//
	//	uint16 ProtocolVersion;
	//	opaque Random[32];
	//
	//	uint8 CipherSuite[2];    /* Cryptographic suite selector */
	//	struct {
	//		ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
	//		Random random;
	//		opaque legacy_session_id<0..32>;
	//		CipherSuite cipher_suites<2..2^16-2>;
	//		opaque legacy_compression_methods<1..2^8-1>;
	//		Extension extensions<8..2^16-1>;
	//	} ClientHello;
	//
	// See https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
	//

	if !cursor.ReadUint16(&ch.ProtocolVersion) {
		return nil, newErrTLSParse("client hello: cannot read protocol version field")
	}

	if !cursor.ReadBytes(&ch.Random, 32) {
		return nil, newErrTLSParse("client hello: cannot read random field")
	}

	if !cursor.ReadUint8LengthPrefixed(&ch.LegacySessionID) {
		return nil, newErrTLSParse("client hello: cannot read legacy session id field")
	}

	if !cursor.ReadUint16LengthPrefixed(&ch.CipherSuites) {
		return nil, newErrTLSParse("client hello: cannot read cipher suites field")
	}

	if !cursor.ReadUint8LengthPrefixed(&ch.LegacyCompressionMethods) {
		return nil, newErrTLSParse("client hello: cannot read legacy compression methods field")
	}

	if !cursor.ReadUint16LengthPrefixed(&ch.Extensions) {
		return nil, newErrTLSParse("client hello: cannot read extensions field")
	}

	if !cursor.Empty() {
		return nil, newErrTLSParse("client hello: unparsed trailing data")
	}

	return ch, nil
}

// TLSExtension is a TLS extension.
type TLSExtension struct {
	// Type is the extension type.
	Type uint16

	// Data contains the extension data.
	Data cryptobyte.String
}

// UnmarshalTLSExtensions unmarshals the extensions.
//
// Return value:
//
// 1. the parsed []*Extensions (on success);
//
// 2. an error (nil on success).
func UnmarshalTLSExtensions(cursor cryptobyte.String) ([]*TLSExtension, error) {
	out := []*TLSExtension{}
	for !cursor.Empty() {
		ext := &TLSExtension{}
		if !cursor.ReadUint16(&ext.Type) {
			return nil, newErrTLSParse("client hello: cannot read extension type")
		}
		if !cursor.ReadUint16LengthPrefixed(&ext.Data) {
			return nil, newErrTLSParse("client hello: cannot read extension data")
		}
		out = append(out, ext)
	}
	return out, nil
}

// FindTLSServerNameExtension returns the first ServerName extension
// in case of success or false in case of failure.
func FindTLSServerNameExtension(exts []*TLSExtension) (*TLSExtension, bool) {
	for _, ext := range exts {
		switch ext.Type {
		case 0: // server_name
			return ext, true
		default:
			continue
		}
	}
	return nil, false
}

// UnmarshalTLSServerNameExtension unmarshals the server name
// from the bytes that consist of the extension value.
func UnmarshalTLSServerNameExtension(cursor cryptobyte.String) (string, error) {
	var serverNameList cryptobyte.String
	if !cursor.ReadUint16LengthPrefixed(&serverNameList) {
		return "", newErrTLSParse("server name: cannot read server name list field")
	}
	if !cursor.Empty() {
		return "", newErrTLSParse("server name: unparsed trailing data")
	}

	var (
		sni   string
		found bool
	)

	for !serverNameList.Empty() {
		var nameType uint8
		if !serverNameList.ReadUint8(&nameType) {
			return "", newErrTLSParse("server name: cannot read name type field")
		}

		switch nameType {
		case 0: // host_name
			var hostName cryptobyte.String
			if !serverNameList.ReadUint16LengthPrefixed(&hostName) {
				return "", newErrTLSParse("server name: cannot read host name field")
			}
			sni = string(hostName)
			found = true

		default:
			continue
		}
	}

	if !found {
		return "", newErrTLSParse("server name: did not find host name entry")
	}
	return sni, nil
}

// ExtractTLSServerName takes in input bytes read from the network, attempts
// to determine whether this is a TLS Handshale message, and if it is a ClientHello,
// and, if affirmative, attempts to extract the server name.
func ExtractTLSHandshake(rawInput []byte, tlsHandshakeMsg []byte, length uint16) ([]byte, uint16, error) {
	if len(rawInput) <= 0 {
		return nil, 0, newErrTLSParse("no data")
	}
	if length != 0 {
		tlsHandshakeMsg = append(tlsHandshakeMsg, rawInput...)
		return tlsHandshakeMsg, length, nil
	}
	rh, _, err := UnmarshalTLSRecordHeader(cryptobyte.String(rawInput))
	if err != nil {
		return nil, 0, err
	}
	tlsHandshakeMsg = append(tlsHandshakeMsg, rh.Rest...)
	return tlsHandshakeMsg, rh.Length, nil
}

// ExtractTLSServerName takes in input bytes read from the network, attempts
// to determine whether this is a TLS Handshale message, and if it is a ClientHello,
// and, if affirmative, attempts to extract the server name.
func ExtractTLServerName(rawInput []byte) (string, error) {
	tlsHandshakeMsg := cryptobyte.String(rawInput)
	hx, err := UnmarshalTLSHandshakeMsg(tlsHandshakeMsg)
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
	return UnmarshalTLSServerNameExtension(snext.Data)
}
