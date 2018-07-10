package channels_test

import (
	"testing"
	"time"

	"bls-ftcosi/cothority/log"
	"bls-ftcosi/cothority/network"
	"bls-ftcosi/cothority/protocols/example/channels"
	"bls-ftcosi/cothority/sda"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

// Tests a 2-node system
func TestNode(t *testing.T) {
	local := sda.NewLocalTest()
	nbrNodes := 2
	_, _, tree := local.GenTree(nbrNodes, false, true, true)
	defer local.CloseAll()

	p, err := local.StartProtocol("ExampleChannels", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := p.(*channels.ProtocolExampleChannels)
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*nbrNodes*2) * time.Millisecond
	select {
	case children := <-protocol.ChildCount:
		log.Lvl2("Instance 1 is done")
		if children != nbrNodes {
			t.Fatal("Didn't get a child-cound of", nbrNodes)
		}
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}
