package ed25519

// #cgo CFLAGS: -DED25519_NO_SEED=1
// #include "ed25519.h"
import "C"

import (
	"crypto/rand"
	"unsafe"
)

const (
	ScalarSize     = 32
	PublicKeySize  = 32
	PrivateKeySize = 64
	SignatureSize  = 64
)

type Scalar [32]byte
type PublicKey [32]byte
type PrivateKey [64]byte
type Signature [64]byte

func CreateSeed() (seed Scalar, err error) {
	_, err = rand.Read(seed[:])
	return seed, err
}

func CreateKeypair(seed Scalar) (publicKey PublicKey, privateKey PrivateKey) {
	C.ed25519_create_keypair(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&privateKey[0])),
		(*C.uchar)(unsafe.Pointer(&seed[0])))
	return publicKey, privateKey
}

func Sign(message []byte, publicKey PublicKey, privateKey PrivateKey) (signature Signature) {
	C.ed25519_sign(
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(C.size_t)(len(message)),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&privateKey[0])))
	return signature
}

func Verify(signature Signature, message []byte, publicKey PublicKey) bool {
	return C.ed25519_verify(
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(C.size_t)(len(message)),
		(*C.uchar)(unsafe.Pointer(&publicKey[0]))) != 0
}

func AddScalar(publicKey PublicKey, privateKey PrivateKey, scalar Scalar) (PublicKey, PrivateKey) {
	var pub PublicKey = publicKey
	var priv PrivateKey = privateKey
	C.ed25519_add_scalar(
		(*C.uchar)(unsafe.Pointer(&pub[0])),
		(*C.uchar)(unsafe.Pointer(&priv[0])),
		(*C.uchar)(unsafe.Pointer(&scalar[0])))
	return pub, priv
}

func KeyExchange(publicKey PublicKey, privateKey PrivateKey) (sharedSecret Scalar) {
	C.ed25519_key_exchange(
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&privateKey[0])))
	return sharedSecret
}
