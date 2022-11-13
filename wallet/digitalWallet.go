package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

type Wallet struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

func NewWallet() *Wallet {
	w := new(Wallet)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	w.privateKey = privateKey
	w.publicKey = &w.privateKey.PublicKey
	//Perfom sha-256 hashing on the public key
	h2 := sha256.New()
	h2.Write(w.PublicKey.X.Bytes())
	h2.Write(w.PublicKey.Y.Bytes())
	digest2 := h2.Sum(nil)
	//Perfom RIPEMD-160 hashing on the result of SHA-256
	h3 := ripemd160.New()
	h3.Write(digest2)
	digest3 := h3.Sum(nil)
	//Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
	vd4 := make([]byte, 0, 21)
	vd4[0] = 0x00
	copy(vd4[1:], digest3[:])
	//Perform SHA-256 hash on the extended RIPEMD-160 result
	h5 := sha256.New()
	h5.Write(vd4)
	digest5 := h5.Sum(nil)
	//Perform SHA-256 hash on the result of the previous SHA-256 hash
	h6 := sha256.New()
	h6.Write(digest5)
	digest6 := h6.Sum(nil)
	checkSum := digest6[:4]
	//Add the 4 checksum bytes from 7 at the end of extended RIPEMD-160 hash
	dc8 := make([]byte, 0, 25)
	copy(dc8[:], vd4[:])
	copy(dc8[21:], checkSum[:])
	address := base58.Encode(dc8)
	//convert an address to base58
	w.blockChainAddress = address

	return w
}

func (w *Wallet) PrivateKey() *ecdsa.PrivateKey {
	return w.privateKey
}

func (w *Wallet) PublicKey() *ecdsa.PublicKey {
	return w.publicKey
}

func (w *Wallet) PrivateKeyStr() string {
	return fmt.Sprintf("%x", w.privateKey.D.Bytes())
}

func (w *Wallet) PublicKeyStr() string {
	return fmt.Sprintf("%x", w.privateKey.D.Bytes())
}

func (w *Wallet) BlockChainAddress() string {
	return w.blockChainAddress()
}
