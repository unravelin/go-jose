package jose

import (
	"crypto/ecdsa"

	josecipher "github.com/unravelin/go-jose/cipher"
)

// createCustomDeriveECDHES - returns a function for generating cek based on 3DS2 spec
func createCustomDeriveECDHES(partyVInfo string) func(alg string, apuData, apvData []byte, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, size int) []byte {
	return func(alg string, apuData, apvData []byte, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, size int) []byte {
		// use an empty algID
		// use an empty apuData value
		// use partyVInfo as apv data
		// pass 32 for key size so full derived key is returned
		key := josecipher.DeriveECDHES("", []byte{}, []byte(partyVInfo), priv, pub, 32)

		if size == 16 {
			// use only first half of key
			key = key[0:16]
		}
		return key
	}
}
