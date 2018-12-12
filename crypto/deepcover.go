package crypto

import (
	"fmt"
    	"encoding/hex"

	deepc "github.com/beyondprotocol/beyondprotocol-sdk/deepcover-client"
)

// DeepCoverLedger structure
type DeepCoverLedger struct {
	RomID []byte
	Index uint
}

// NewDeepCoverLedger creates new DeepCover ledger object
func NewDeepCoverLedger(romID []byte) *DeepCoverLedger {
	return &DeepCoverLedger{
		RomID: romID,
		Index: 0,
	}
}

// FindDeepCover returns DeepCover found on the RPi
func FindDeepCover() (*DeepCoverLedger, error) {
	newDeepCoverLedger := DeepCoverLedger{RomID: deepc.GetDcID()}
	return &newDeepCoverLedger, nil
}

// SignSECP256R1 returns the signature of the input data
func (dc *DeepCoverLedger) SignSECP256R1(txBytes []byte) ([]byte, error) {
	return deepc.SignData(deepc.CalcucateMessageDigest(txBytes, dc.RomID)), nil
}

// GetPublicKeySECP256R1 returns the DeepCover public key
func (dc *DeepCoverLedger) GetPublicKeySECP256R1() ([]byte, error) {
	var publicKey []byte
        const pubkeyMagicPrefix = 0x4
        publicKey = append(publicKey, pubkeyMagicPrefix)
        publicKey = append(publicKey, deepc.GetPubKeyA()...)

        fmt.Println("Retrieved public key from DeepCover:\n")
        fmt.Println(hex.EncodeToString(publicKey))

        return publicKey, nil
}

// GetRomID returns the DeepCover ID (romID)
func (dc *DeepCoverLedger) GetRomID() []byte {
	dcID := deepc.GetDcID()
	fmt.Println("DeepCover ID: ", deepc.Bytes2HexString(dcID))
	return dcID
}

func init() {
	//TODO:
	// Init DeepCover
	discoverDeepCover = func() (DeepCoverSECP256R1, error) {
		dc, err := FindDeepCover()
		if err != nil {
			return nil, err
		}
		return dc, nil
	}
}
