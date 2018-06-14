package protocol


import (
	"testing"
	"time"

	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/kyber.v2/group/edwards25519"
)

var tSuite = edwards25519.NewBlakeSHA256Ed25519()


func TestNode(t *testing.T) {

	proposal := []byte("dedis")
	defaultTimeout := 5 * time.Second
	nodes := []int{3, 4, 9, 13, 40}

	for _, nbrNodes := range nodes {
		local := onet.NewLocalTest(tSuite)
		_, _, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes - 1, true)
		log.Lvl3(tree.Dump())

		pi, err := local.CreateProtocol(DefaultProtocolName, tree)
		if err != nil {
			local.CloseAll()
			t.Fatal("Error in creation of protocol:", err)
		}

		protocol := pi.(*PbftProtocol)
		protocol.Msg = proposal
		protocol.Timeout = defaultTimeout

		err = protocol.Start()
		if err != nil {
			local.CloseAll()
			t.Fatal(err)
		}

		select {
		case finalReply := <-protocol.FinalReply:
			log.Lvl3("Leader sent final reply")
			_ = finalReply
		case <-time.After(defaultTimeout * 2):
			t.Fatal("Leader never got enough final replies, timed out")
		}

	}
}

