package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"
)

var (
	resBytes []byte
	resBool  bool
)

func BenchmarkCalculateHMACSignature(b *testing.B) {
	var r []byte
	secret := make([]byte, HMACSignatureSize)
	if _, err := rand.Read(secret); err != nil {
		b.Fatalf("CSPRNG failure: %v", err)
	}
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		r = CalculateHMACSignature(secret, "username", 0)
	}
	resBytes = r
}

func BenchmarkVerifyHMACLoginAndPassword(b *testing.B) {
	var r bool
	secret := make([]byte, HMACSignatureSize)
	if _, err := rand.Read(secret); err != nil {
		b.Fatalf("CSPRNG failure: %v", err)
	}
	username := "username"
	expire := time.Now().Add(time.Hour).Unix()
	mac := CalculateHMACSignature(secret, username, expire)
	token := HMACToken{
		Expire: expire,
	}
	copy(token.Signature[:], mac)
	var resBuf bytes.Buffer
	enc := base64.NewEncoder(base64.RawURLEncoding, &resBuf)
	if err := binary.Write(enc, binary.BigEndian, &token); err != nil {
		b.Fatalf("token encoding failed: %v", err)
	}
	enc.Close()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		r = VerifyHMACLoginAndPassword(secret, username, resBuf.String())
		if !r {
			b.Fail()
		}
	}
	resBool = r
}
