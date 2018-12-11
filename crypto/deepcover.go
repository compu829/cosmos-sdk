package crypto

 import (
 	deepc "github.com/beyondprotocol/beyondprotocol-sdk/deepcover-client"
	"fmt"
 )

type DeepCoverLedger struct {
	RomID []byte
	Index uint
}

func NewDeepCoverLedger(romID []byte) *DeepCoverLedger {
	return &DeepCoverLedger{
		RomID: romID,
		Index: 0,
	}
}

func FindDeepCover() (*DeepCoverLedger, error) {
	newDeepCoverLedger := DeepCoverLedger{RomID: []byte("mock")}
	return &newDeepCoverLedger, nil
}

func (dc *DeepCoverLedger) SignSECP256R1(txBytes []byte) ([]byte, error) {
	return []byte("mock"), nil
}

func (dc *DeepCoverLedger) GetPublicKeySECP256R1() ([]byte, error) {
        dcID := deepc.GetDcID()
	fmt.Println(dcID)
	return []byte("ED44653F01F42FE33BEE8FF29E9A2BBDE0543CFBA8E716EC338DC527DEC1AEC5"), nil
}

func (dc *DeepCoverLedger) GetRomID() []byte {
	return []byte("mock")
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
