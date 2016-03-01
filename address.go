// Copyright (c) 2013, 2014 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcutil

import (
	//	"encoding/hex"
	"errors"
	"fmt"

	//	"golang.org/x/crypto/ripemd160"

	"github.com/FactomProject/btcd/btcec"
	"github.com/FactomProject/btcd/chaincfg"
	"github.com/FactomProject/btcutil/base58"

	"github.com/FactomProject/FactomCode/util"
	"github.com/FactomProject/go-spew/spew"
)

var _ = util.Trace

const utilRCDHashSize = 32

const disableSpew = true

type utilRCDHash [utilRCDHashSize]byte // this is our factoid address

var (
	// ErrChecksumMismatch describes an error where decoding failed due
	// to a bad checksum.
	ErrChecksumMismatch = errors.New("checksum mismatch")

	// ErrUnknownAddressType describes an error where an address can not
	// decoded as a specific address type due to the string encoding
	// begining with an identifier byte unknown to any standard or
	// registered (via chaincfg.Register) network.
	ErrUnknownAddressType = errors.New("unknown address type")

	// ErrAddressCollision describes an error where an address can not
	// be uniquely determined as either a pay-to-pubkey-hash or
	// pay-to-script-hash address since the leading identifier is used for
	// describing both address kinds, but for different networks.  Rather
	// than assuming or defaulting to one or the other, this error is
	// returned and the caller must decide how to decode the address.
	ErrAddressCollision = errors.New("address collision")
)

// Address is an interface type for any type of destination a transaction
// output may spend to.  This includes pay-to-pubkey (P2PK), pay-to-pubkey-hash
// (P2PKH), and pay-to-script-hash (P2SH).  Address is designed to be generic
// enough that other kinds of addresses may be added in the future without
// changing the decoding and encoding API.
type Address interface {
	// String returns the string encoding of the transaction output
	// destination.
	//
	// Please note that String differs subtly from EncodeAddress: String
	// will return the value as a string without any conversion, while
	// EncodeAddress may convert destination types (for example,
	// converting pubkeys to P2PKH addresses) before encoding as a
	// payment address string.
	String() string

	// EncodeAddress returns the string encoding of the payment address
	// associated with the Address value.  See the comment on String
	// for how this method differs from String.
	EncodeAddress() string

	// ScriptAddress returns the raw bytes of the address to be used
	// when inserting the address into a txout's script.
	ScriptAddress() []byte

	// IsForNet returns whether or not the address is associated with the
	// passed bitcoin network.
	IsForNet(*chaincfg.Params) bool
}

// AddressPubKeyHash is an Address for a pay-to-pubkey-hash (P2PKH)
// transaction.
type AddressPubKeyHash struct {
	//	hash  [ripemd160.Size]byte
	hash [utilRCDHashSize]byte
	//	rcd   utilRCDHash
	netID byte
}

// NewAddressPubKeyHash returns a new AddressPubKeyHash.  pkHash mustbe 20
// bytes.
func NewAddressPubKeyHash(pkHash []byte, net *chaincfg.Params) (*AddressPubKeyHash, error) {
	if !disableSpew {
		//util.Trace(spew.Sdump(pkHash))
	}
	return newAddressPubKeyHash(pkHash, net.PubKeyHashAddrID)
}

// newAddressPubKeyHash is the internal API to create a pubkey hash address
// with a known leading identifier byte for a network, rather than looking
// it up through its parameters.  This is useful when creating a new address
// structure from a string encoding where the identifer byte is already
// known.
func newAddressPubKeyHash(pkHash []byte, netID byte) (*AddressPubKeyHash, error) {
	if !disableSpew {
		//util.Trace(spew.Sdump(pkHash))
	}
	// Check for a valid pubkey hash length.
	//	if len(pkHash) != ripemd160.Size {
	if len(pkHash) != utilRCDHashSize {
		return nil, errors.New("pkHash must be 32 bytes")
	}

	addr := &AddressPubKeyHash{netID: netID}
	copy(addr.hash[:], pkHash)
	return addr, nil
}

// EncodeAddress returns the string encoding of a pay-to-pubkey-hash
// address.  Part of the Address interface.
func (a *AddressPubKeyHash) EncodeAddress() string {
	if !disableSpew {
		//util.Trace(spew.Sdump(a.hash[:]))
	}

	ret_string := encodeAddress(a.hash[:], a.netID)
	//util.Trace(ret_string)

	return ret_string
}

// ScriptAddress returns the bytes to be included in a txout script to pay
// to a pubkey hash.  Part of the Address interface.
func (a *AddressPubKeyHash) ScriptAddress() []byte {
	ret_bytes := a.hash[:]
	if !disableSpew {
		//util.Trace(spew.Sdump(ret_bytes))
	}

	return ret_bytes
}

// IsForNet returns whether or not the pay-to-pubkey-hash address is associated
// with the passed bitcoin network.
func (a *AddressPubKeyHash) IsForNet(net *chaincfg.Params) bool {
	return a.netID == net.PubKeyHashAddrID
}

// String returns a human-readable string for the pay-to-pubkey-hash address.
// This is equivalent to calling EncodeAddress, but is provided so the type can
// be used as a fmt.Stringer.
func (a *AddressPubKeyHash) String() string {
	ret_string := a.EncodeAddress()
	//util.Trace(ret_string)

	return ret_string
}

// Hash160 returns the underlying array of the pubkey hash.  This can be useful
// when an array is more appropiate than a slice (for example, when used as map
// keys).
// func (a *AddressPubKeyHash) Hash160() *[ripemd160.Size]byte {
func (a *AddressPubKeyHash) Hash160() *[utilRCDHashSize]byte {
	if !disableSpew {
		//util.Trace(spew.Sdump(a))
	}

	return &a.hash
}

// PubKeyFormat describes what format to use for a pay-to-pubkey address.
type PubKeyFormat int

const (
	// PKFUncompressed indicates the pay-to-pubkey address format is an
	// uncompressed public key.
	PKFUncompressed PubKeyFormat = iota

	// PKFCompressed indicates the pay-to-pubkey address format is a
	// compressed public key.
	PKFCompressed

	// PKFHybrid indicates the pay-to-pubkey address format is a hybrid
	// public key.
	PKFHybrid
)

// AddressPubKeyHash returns the pay-to-pubkey address converted to a
// pay-to-pubkey-hash address.  Note that the public key format (uncompressed,
// compressed, etc) will change the resulting address.  This is expected since
// pay-to-pubkey-hash is a hash of the serialized public key which obviously
// differs with the format.  At the time of this writing, most Bitcoin addresses
// are pay-to-pubkey-hash constructed from the uncompressed public key.
func (a *AddressPubKey) AddressPubKeyHash() *AddressPubKeyHash {
	panic(errors.New("plain PubKey format is not supported"))

	addr := &AddressPubKeyHash{netID: a.pubKeyHashID}
	copy(addr.hash[:], Hash160(a.serialize()))
	return addr
}

// PubKey returns the underlying public key for the address.
func (a *AddressPubKey) PubKey() *btcec.PublicKey {
	panic(errors.New("plain PubKey format is not supported"))

	return a.pubKey
}

// Factom NEW ////////////////////////////////////

func encodeAddress(hash160 []byte, netID byte) string {
	return EncodeAddr(hash160)
}

func EncodeAddr(hash []byte) string {
	if len(hash) != utilRCDHashSize {
		panic(errors.New(fmt.Sprintf("hash len is wrong: %d", len(hash))))
	}

	human_addr := base58.CheckEncode(hash[:], 0)

	fmt.Println("EncodeAddr()= " + human_addr)

	return human_addr
}

// DecodeAddress decodes the string encoding of an address and returns
// the Address if addr is a valid encoding for a known address type.
//
// The bitcoin network the address is associated with is extracted if possible.
// When the address does not encode the network, such as in the case of a raw
// public key, the address will be associated with the passed defaultNet.
// func DecodeAddress(addr string, defaultNet *chaincfg.Params) (Address, error) {
func old_DecodeAddr(addr string) (Address, error) {
	//util.Trace("DecodeAddress(" + addr + ")")
	//util.Trace(fmt.Sprintf("len= %d", len(addr)))

	/*
		// Serialized public keys are either 65 bytes (130 hex chars) if
		// uncompressed/hybrid or 33 bytes (66 hex chars) if compressed.
		//	if len(addr) == 130 || len(addr) == 66 {
		if 52 == len(addr) {
			serializedPubKey, err := hex.DecodeString(addr)

			if err != nil {
				//util.Trace(fmt.Sprintf("ERROR: %v", err))
				return nil, err
			}
			//util.Trace()
			return NewAddressPubKey(serializedPubKey, &chaincfg.MainNetParams)
		}

		return nil, errors.New("decoded address is of unknown format")

		panic(12300)
	*/

	if 52 != len(addr) {
		panic(errors.New("Factoid address not 52 characters long!"))
	}
	//util.Trace()

	// Switch on decoded length to determine the type.
	//	decoded, netID, err := base58.CheckDecode(addr)
	decoded, _, _, err := base58.CheckDecode(addr)
	if err != nil {
		if err == base58.ErrChecksum {
			return nil, ErrChecksumMismatch
		}
		fmt.Println(err)
		return nil, errors.New("decoded address is of unknown format")
	}

	//	//util.Trace("decoded= " + spew.Sdump(decoded))

	return NewAddressPubKey(decoded, &chaincfg.MainNetParams)

	/*
		switch len(decoded) {
		case ripemd160.Size: // P2PKH or P2SH
			isP2PKH := chaincfg.IsPubKeyHashAddrID(netID)
			isP2SH := chaincfg.IsScriptHashAddrID(netID)
			switch hash160 := decoded; {
			case isP2PKH && isP2SH:
				return nil, ErrAddressCollision
							case isP2PKH:
								return newAddressPubKeyHash(hash160, netID)
					case isP2SH:
						return newAddressScriptHashFromHash(hash160, netID)
			default:
				return nil, ErrUnknownAddressType
			}

		default:
			return nil, errors.New("decoded address is of unknown size")
		}
	*/
}

// DecodeAddress decodes the string encoding of an address and returns
// the Address if addr is a valid encoding for a known address type.
//
// The bitcoin network the address is associated with is extracted if possible.
// When the address does not encode the network, such as in the case of a raw
// public key, the address will be associated with the passed defaultNet.
func DecodeAddress(addr string, defaultNet *chaincfg.Params) (Address, error) {
	//util.Trace("DecodeAddress(" + addr + ")")
	//util.Trace(fmt.Sprintf("len= %d", len(addr)))

	if 52 != len(addr) {
		panic(errors.New("Factoid address not 52 characters long!"))
	}
	//util.Trace()

	/*
		// Serialized public keys are either 65 bytes (130 hex chars) if
		// uncompressed/hybrid or 33 bytes (66 hex chars) if compressed.
		if len(addr) == 130 || len(addr) == 66 {
			serializedPubKey, err := hex.DecodeString(addr)
			if err != nil {
				return nil, err
			}
			return NewAddressPubKey(serializedPubKey, defaultNet)
		}
	*/

	// Switch on decoded length to determine the type.
	//	decoded, netID, byte2, err := base58.CheckDecode(addr)
	decoded, netID, _, err := base58.CheckDecode(addr)
	if err != nil {
		if err == base58.ErrChecksum {
			return nil, ErrChecksumMismatch
		}
		return nil, errors.New("decoded address is of unknown format")
	}
	if !disableSpew {
		//util.Trace("decoded= " + spew.Sdump(decoded))
	}

	/*
		switch len(decoded) {
		case ripemd160.Size: // P2PKH or P2SH
			isP2PKH := chaincfg.IsPubKeyHashAddrID(netID)
			isP2SH := chaincfg.IsScriptHashAddrID(netID)
			switch hash160 := decoded; {
			case isP2PKH && isP2SH:
				return nil, ErrAddressCollision
			case isP2PKH:
				return newAddressPubKeyHash(hash160, netID)
			case isP2SH:
				return newAddressScriptHashFromHash(hash160, netID)
			default:
				return nil, ErrUnknownAddressType
			}

		default:
			return nil, errors.New("decoded address is of unknown size")
		}
	*/

	hash160 := decoded

	return newAddressPubKeyHash(hash160, netID)
}
