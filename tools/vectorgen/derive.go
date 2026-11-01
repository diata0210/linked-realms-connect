package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

var identityPath = []uint32{0x80000000, 0x80000000}
var walletPath = []uint32{0x80000001, 0x80000000}

func mac(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	_, err := h.Write(data)
	check(err)
	return h.Sum(nil)
}

// Independent HMAC composition, used only as an offline fixture cross-check.
// It does not share crypto/hmac or the primary derivation loop.
func manualMAC(key, data []byte) []byte {
	if len(key) > 128 {
		h := sha512.Sum512(key)
		key = h[:]
	}
	inner, outer := make([]byte, 128), make([]byte, 128)
	copy(inner, key)
	copy(outer, key)
	for i := range inner {
		inner[i] ^= 0x36
		outer[i] ^= 0x5c
	}
	a := sha512.Sum512(append(inner, data...))
	b := sha512.Sum512(append(outer, a[:]...))
	return b[:]
}

func slip(seed []byte, path []uint32) (key, chain []byte) {
	i := mac([]byte("ed25519 seed"), seed)
	for _, index := range path {
		must(index >= 0x80000000, "nonhardened SLIP path")
		data := append([]byte{0}, i[:32]...)
		data = binary.BigEndian.AppendUint32(data, index)
		i = mac(i[32:], data)
	}
	return i[:32], i[32:]
}

func independentSlip(seed []byte, path []uint32) []byte {
	if len(path) == 0 {
		return manualMAC([]byte("ed25519 seed"), seed)
	}
	parent := independentSlip(seed, path[:len(path)-1])
	var data [37]byte
	copy(data[1:33], parent[:32])
	binary.BigEndian.PutUint32(data[33:], path[len(path)-1])
	return manualMAC(parent[32:], data[:])
}

func bip(seed []byte, path []uint32) *hdkeychain.ExtendedKey {
	k, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	check(err)
	for _, index := range path {
		k, err = k.Derive(index)
		check(err)
	}
	return k
}

// Independent fixed-path hardened CKD using stdlib HMAC/big.Int, not hdkeychain.
func independentBIP(seed []byte, path []uint32) (key, chain []byte) {
	i := mac([]byte("Bitcoin seed"), seed)
	n := new(big.Int).SetBytes(unhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"))
	k := new(big.Int).SetBytes(i[:32])
	must(k.Sign() > 0 && k.Cmp(n) < 0, "invalid BIP master")
	c := append([]byte{}, i[32:]...)
	for _, index := range path {
		must(index >= 0x80000000, "independent BIP accepts hardened only")
		data := make([]byte, 37)
		k.FillBytes(data[1:33])
		binary.BigEndian.PutUint32(data[33:], index)
		i = mac(c, data)
		left := new(big.Int).SetBytes(i[:32])
		must(left.Cmp(n) < 0, "invalid BIP child left")
		k.Add(k, left).Mod(k, n)
		must(k.Sign() > 0, "invalid BIP child zero")
		c = append([]byte{}, i[32:]...)
	}
	return k.FillBytes(make([]byte, 32)), c
}

func pub(seed []byte) []byte { return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey) }

func derivations() []M {
	seeds := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
	}
	var out []M
	for _, seedHex := range seeds {
		seed := unhex(seedHex)
		for _, profile := range []string{"identity", "wallet_A", "wallet_B"} {
			path, pathText := walletPath, "m/1'/0'"
			if profile == "identity" {
				path, pathText = identityPath, "m/0'/0'"
			}
			var key, chain, public []byte
			algorithm := "SLIP-0010 Ed25519"
			if profile == "wallet_A" {
				algorithm = "BIP32 secp256k1"
				ext := bip(seed, path)
				p, err := ext.ECPrivKey()
				check(err)
				key, chain, public = p.Serialize(), ext.ChainCode(), p.PubKey().SerializeCompressed()
				k2, c2 := independentBIP(seed, path)
				must(bytes.Equal(key, k2) && bytes.Equal(chain, c2), "BIP independent mismatch")
				_, p2 := btcec.PrivKeyFromBytes(k2)
				must(bytes.Equal(public, p2.SerializeCompressed()), "BIP public mismatch")
			} else {
				key, chain = slip(seed, path)
				public = pub(key)
				second := independentSlip(seed, path)
				must(bytes.Equal(append(append([]byte{}, key...), chain...), second), "SLIP independent mismatch")
			}
			out = append(out, M{"name": profile + "/" + seedHex, "root_seed_hex": seedHex, "profile": profile, "algorithm": algorithm, "path": pathText, "indices": path, "private_hex": hex(key), "chain_code_hex": hex(chain), "public_hex": hex(public), "independent_agreement": true})
		}
	}
	return out
}

func knownAnswers() []M {
	seed := unhex("000102030405060708090a0b0c0d0e0f")
	paths := [][]uint32{nil, {0x80000000}}
	slipKeys := []string{"2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"}
	slipChains := []string{"90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"}
	slipPubs := []string{"a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed", "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"}
	xprvs := []string{"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"}
	var out []M
	for i, path := range paths {
		name := []string{"m", "m/0'"}[i]
		k, c := slip(seed, path)
		must(hex(k) == slipKeys[i] && hex(c) == slipChains[i] && hex(pub(k)) == slipPubs[i], "published SLIP answer failed")
		out = append(out, M{"name": "SLIP-0010 test vector 1 for ed25519 / " + name, "source": "https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-ed25519", "seed_hex": hex(seed), "path": name, "private_hex": slipKeys[i], "chain_code_hex": slipChains[i], "public_hex": slipPubs[i], "agreement": true})
		ext := bip(seed, path)
		must(ext.String() == xprvs[i], "published BIP answer failed")
		k2, c2 := independentBIP(seed, path)
		p, err := ext.ECPrivKey()
		check(err)
		must(bytes.Equal(p.Serialize(), k2) && bytes.Equal(ext.ChainCode(), c2), "published BIP independent mismatch")
		out = append(out, M{"name": "BIP32 test vector 1 / " + name, "source": "https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1", "seed_hex": hex(seed), "path": name, "xprv": xprvs[i], "private_hex": hex(k2), "chain_code_hex": hex(c2), "public_hex": hex(p.PubKey().SerializeCompressed()), "agreement": true})
	}
	// Official leading-zero regression, guards fixed-width child serialization.
	zseed := unhex("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")
	zpath := []uint32{0x80000000, 0x80000001}
	z := bip(zseed, zpath)
	expected := "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"
	must(z.String() == expected, "BIP vector4 leading-zero mismatch")
	k, c := independentBIP(zseed, zpath)
	pk, err := z.ECPrivKey()
	check(err)
	must(bytes.Equal(k, pk.Serialize()) && bytes.Equal(c, z.ChainCode()), "independent leading-zero mismatch")
	out = append(out, M{"name": "BIP32 test vector 4 / m/0'/1' (leading zeros)", "source": "https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-4", "seed_hex": hex(zseed), "path": "m/0'/1'", "xprv": expected, "private_hex": hex(k), "chain_code_hex": hex(c), "agreement": true})
	return out
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
func must(ok bool, message string) {
	if !ok {
		panic(fmt.Errorf("vector assertion: %s", message))
	}
}
