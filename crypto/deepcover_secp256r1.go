package crypto

import (
	"fmt"

	tmcrypto "github.com/tendermint/tendermint/crypto"
	dcsecp256r1 "github.com/tendermint/tendermint/crypto/secp256r1"
)

var (
	// discoverDeepCover defines a function to be invoked at runtime for discovering
	// a connected DeepCover device.
	discoverDeepCover discoverDeepCoverFn
)

type (
	// discoverDeepCoverFn defines a DeepCover discovery function that returns a
	// connected device or an error upon failure.
	discoverDeepCoverFn func() (DeepCoverSECP256R1, error)
	// DeepCoverSECP256R1 reflects an interface a DeepCover API must implement for
	// the SECP256R1 scheme.
	DeepCoverSECP256R1 interface {
		GetPublicKeySECP256R1() ([]byte, error)
		SignSECP256R1([]byte) ([]byte, error)
	}

	// We cache the PubKey from the first call to use it later.
	PrivKeyDeepCoverSecp256r1 struct {
		// CachedPubKey should be private, but we want to encode it via
		// go-amino so we can view the address later
		CachedPubKey tmcrypto.PubKey
		deepcover    DeepCoverSECP256R1
	}
)

// NewPrivKeyDeepCoverSecp256r1 will generate a new key and store the public key
// for later use.
func NewPrivKeyDeepCoverSecp256r1() (tmcrypto.PrivKey, error) {
	deepCover, err := discoverDeepCover()

	pkeydeep := &PrivKeyDeepCoverSecp256r1{deepcover: deepCover}

	pubKey, err := pkeydeep.getPubKey()
	if err != nil {
		return nil, err
	}

	pkeydeep.CachedPubKey = pubKey
	return pkeydeep, err
}

// Implement Tendermint PrivKey interface
// PubKey returns the cached public key.
func (pkeydeep PrivKeyDeepCoverSecp256r1) PubKey() tmcrypto.PubKey {
	return pkeydeep.CachedPubKey
}

// ValidateKey allows us to verify the sanity of a public key after loading it
// from disk.
func (pkeydeep PrivKeyDeepCoverSecp256r1) ValidateKey() error {
	// getPubKey will return an error if the ledger is not
	pub, err := pkeydeep.getPubKey()
	if err != nil {
		return err
	}

	// verify this matches cached address
	if !pub.Equals(pkeydeep.CachedPubKey) {
		return fmt.Errorf("cached key does not match retrieved key")
	}

	return nil
}

// AssertIsPrivKeyInner implements the PrivKey interface. It performs a no-op.
func (pkeydeep *PrivKeyDeepCoverSecp256r1) AssertIsPrivKeyInner() {}

// Bytes implements the PrivKey interface. It stores the cached public key so
// we can verify the same key when we reconnect to a device.
func (pkeydeep PrivKeyDeepCoverSecp256r1) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(pkeydeep)
}

// Equals implements the PrivKey interface. It makes sure two private keys
// refer to the same public key.
func (pkeydeep PrivKeyDeepCoverSecp256r1) Equals(other tmcrypto.PrivKey) bool {
	if deepcover, ok := other.(*PrivKeyDeepCoverSecp256r1); ok {
		return pkeydeep.CachedPubKey.Equals(deepcover.CachedPubKey)
	}

	return false
}

// Sign calls the DeepCover and stores the PubKey for future use.
//
// Communication is checked on NewPrivKeyDeepCover and PrivKeyFromBytes, returning
// an error, so this should only trigger if the private key is held in memory
// for a while before use.
func (pkeydeep PrivKeyDeepCoverSecp256r1) Sign(msg []byte) ([]byte, error) {
	sig, err := pkeydeep.signDeepCoverSecp256r1(msg)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// getPubKey reads the pubkey from the device itself
// since this involves IO, it may return an error, which is not exposed
// in the PubKey interface, so this function allows better error handling
func (pkeydeep PrivKeyDeepCoverSecp256r1) getPubKey() (key tmcrypto.PubKey, err error) {
	key, err = pkeydeep.pubkeyDeepCoverSecp256r1()
	if err != nil {
		return key, fmt.Errorf("Internal error during retrieval of DeepCover public key. Details: %v", err)
	}
	return key, err
}

func (pkeydeep PrivKeyDeepCoverSecp256r1) signDeepCoverSecp256r1(msg []byte) ([]byte, error) {
	return pkeydeep.deepcover.SignSECP256R1(msg)
}

func (pkeydeep PrivKeyDeepCoverSecp256r1) pubkeyDeepCoverSecp256r1() (pub tmcrypto.PubKey, err error) {
	key, err := pkeydeep.deepcover.GetPublicKeySECP256R1()
	if err != nil {
		return nil, fmt.Errorf("error fetching public key: %v", err)
	}

	var pk dcsecp256r1.PubKeySecp256r1

	copy(pk[:], key)

	return pk, nil
}
