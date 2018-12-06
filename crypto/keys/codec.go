package keys

import (
	ccrypto "github.com/cosmos/cosmos-sdk/crypto"
	amino "github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/crypto/encoding/amino"
)

var cdc = amino.NewCodec()

func init() {
	cryptoAmino.RegisterAmino(cdc)
	cdc.RegisterInterface((*Info)(nil), nil)
	cdc.RegisterConcrete(ccrypto.PrivKeyLedgerSecp256k1{},
		"tendermint/PrivKeyLedgerSecp256k1", nil)
	cdc.RegisterConcrete(ccrypto.PrivKeyDeepCoverSecp256r1{},
		"tendermint/PrivKeyDeepCoverSecp256r1", nil)
	cdc.RegisterConcrete(localInfo{}, "crypto/keys/localInfo", nil)
	cdc.RegisterConcrete(ledgerInfo{}, "crypto/keys/ledgerInfo", nil)
	cdc.RegisterConcrete(offlineInfo{}, "crypto/keys/offlineInfo", nil)
	cdc.RegisterConcrete(deepCoverInfo{}, "crypto/keys/deepCoverInfo", nil)
}
