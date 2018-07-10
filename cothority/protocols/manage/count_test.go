package manage_test

import (
	"testing"
	"time"

	"bls-ftcosi/cothority/log"
	"bls-ftcosi/cothority/network"
	"bls-ftcosi/cothority/protocols/manage"
	"bls-ftcosi/cothority/sda"
)

// Tests a 2-node system
func TestCount(t *testing.T) {
	local := sda.NewLocalTest()
	nbrNodes := 2
	_, _, tree := local.GenTree(nbrNodes, false, true, true)
	defer local.CloseAll()

	pi, err := local.StartProtocol("Count", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := pi.(*manage.ProtocolCount)
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*nbrNodes*2) * time.Millisecond
	select {
	case children := <-protocol.Count:
		log.Lvl2("Instance 1 is done")
		if children != nbrNodes {
			t.Fatal("Didn't get a child-cound of", nbrNodes)
		}
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}
