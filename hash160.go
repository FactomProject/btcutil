// Copyright (c) 2013-2014 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcutil

import (
	//	"hash"
	//	"golang.org/x/crypto/ripemd160"
	//	"github.com/FactomProject/fastsha256"

	"github.com/FactomProject/FactomCode/util"
)

var _ = util.Trace

/*

// Calculate the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// Hash160 calculates the hash ripemd160(sha256(b)).
func Hash160(buf []byte) []byte {
	//util.Trace()
	return calcHash(calcHash(buf, fastsha256.New()), ripemd160.New())
}
*/

// Hash160 calculates the hash ripemd160(sha256(b)).
func Hash160(buf []byte) []byte {
	//util.Trace()
	//	return calcHash(calcHash(buf, fastsha256.New()), ripemd160.New())
	return buf
}
