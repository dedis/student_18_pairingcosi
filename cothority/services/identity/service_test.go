package identity

import (
	"testing"

	"bls-ftcosi/cothority/log"
	"bls-ftcosi/cothority/network"
	"bls-ftcosi/cothority/sda"
	"gopkg.in/dedis/crypto.v0/config"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestService_AddIdentity(t *testing.T) {
	local := sda.NewLocalTest()
	defer local.CloseAll()
	_, el, s := local.MakeHELS(5, identityService)
	service := s.(*Service)

	keypair := config.NewKeyPair(network.Suite)
	il := NewConfig(50, keypair.Public, "one")
	msg, err := service.AddIdentity(nil, &AddIdentity{il, el})
	log.ErrFatal(err)
	air := msg.(*AddIdentityReply)

	data := air.Data
	id, ok := service.Identities[string(data.Hash)]
	assert.True(t, ok)
	assert.NotNil(t, id)
}
