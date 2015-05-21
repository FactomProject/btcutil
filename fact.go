package btcutil

import (
	//	"crypto/ecdsa"
	"errors"
	"fmt"
	//	"math/big"

	"github.com/FactomProject/btcd/btcec"

	"github.com/FactomProject/FactomCode/util"
	"github.com/davecgh/go-spew/spew"
)

const utilRCDHashSize = 32

type utilRCDHash [utilRCDHashSize]byte // this is out factoid address

// PublicKey is an ecdsa.PublicKey with additional functions to
// serialize in uncompressed, compressed, and hybrid formats.
// type PublicKey ecdsa.PublicKey

// ParsePubKey parses a public key for a koblitz curve from a bytestring into a
// ecdsa.Publickey, verifying that it is valid. It supports compressed,
// uncompressed and hybrid signature formats.
// func ParsePubKey(pubKeyStr []byte, curve *KoblitzCurve) (key *PublicKey, err error) {
func ParsePubKey(pubKeyStr []byte) (key *btcec.PublicKey, err error, rcdh *utilRCDHash) {
	//	util.Trace("parsePubKey (str): " + spew.Sdump(pubKeyStr))

	pubkey := btcec.PublicKey{}
	newrcd := utilRCDHash{}

	if utilRCDHashSize != len(pubKeyStr) {
		panic(errors.New("ParsePubKey PROBLEM !!!"))
	}

	copy(newrcd[:], pubKeyStr)

	util.Trace("parsePubKey (pubkey): " + spew.Sdump(pubkey))
	util.Trace("parsePubKey (newrcd): " + spew.Sdump(newrcd))

	// use the RCD hash as the pubkey off the Bitcoin curve for temporary wallet integration
	fakebtc := []byte{0x2}
	fakebtc = append(fakebtc, pubKeyStr...)

	pk, err := btcec.ParsePubKey(fakebtc, btcec.S256())

	if nil == err {
		pubkey.X = pk.X
		pubkey.Y = pk.Y
	} else {
		fmt.Println(err)
	}

	return &pubkey, nil, &newrcd
}

// SerializeCompressed serializes a public key in a 33-byte compressed format.
// func (p *btcec.PublicKey) SerializePK() []byte {
func notneeded_SerializePK() []byte {
	util.Trace()

	/*
		b := make([]byte, 0, 32)
			format := pubkeyCompressed
			if isOdd(p.Y) {
				format |= 0x1
			}
			b = append(b, format)
	*/

	util.Trace()
	/*
		px := p.X.Bytes()

		//	return paddedAppend(32, b, p.X.Bytes())

		util.Trace()
		ret_val := paddedAppend(32, b, px)

		util.Trace()
	*/
	ret_val := make([]byte, utilRCDHashSize)

	return ret_val
}
