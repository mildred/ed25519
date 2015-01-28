package ed25519

import (
	"io"
	"math/rand"
	"testing"
	"time"
)

type randGen struct {
	rand.Rand
}

func (r randGen) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = byte(r.Rand.Intn(255))
	}
	return len(p), nil
}

var randio io.Reader = randGen{*rand.New(rand.NewSource(time.Now().UnixNano()))}

func createPseudoSeed(t *testing.T) (s Scalar) {
	_, err := randio.Read(s[:])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignature(t *testing.T) {
	pk, sk := CreateKeypair(createPseudoSeed(t))
	text := createPseudoSeed(t)

	sig := Sign(text[:], pk, sk)
	if !Verify(sig, text[:], pk) {
		t.Fatal("Verify signature failed")
	}

	randio.Read(sig[:])
	if Verify(sig, text[:], pk) {
		t.Fatal("Verify signature success for random signature")
	}
}
