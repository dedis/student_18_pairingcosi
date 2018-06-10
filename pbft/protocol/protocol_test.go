package protocol

/*
The test-file should at the very least run the protocol for a varying number
of nodes. It is even better practice to test the different methods of the
protocol, as in Test Driven Development.
*/

import (
	"testing"
	"time"
	//"fmt"
	//"reflect"
	//"gopkg.in/dedis/kyber.v2/suites"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"

	//"gopkg.in/dedis/kyber.v2/sign/schnorr"
	//"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/group/edwards25519"
	//"gopkg.in/dedis/kyber.v2/sign/eddsa"
)

var tSuite = edwards25519.NewBlakeSHA256Ed25519() // suites.MustFind("Ed25519")
/*
func TestMain(m *testing.M) {
	log.MainTest(m)
}
*/

// Tests a 2, 5 and 13-node system. It is good practice to test different
// sizes of trees to make sure your protocol is stable.
func TestNode(t *testing.T) {

	proposal := []byte("dedis")
	defaultTimeout := 5 * time.Second
	nodes := []int{100} // []int{2, 5, 13}

	for _, nbrNodes := range nodes {
		local := onet.NewLocalTest(tSuite)
		_, _, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes - 1, true)
		log.Lvl3(tree.Dump())

/*
		pubKeysMap := make(map[string]kyber.Point) // edwards25519.point
		for _, node := range tree.List() {
			//fmt.Println(node.ServerIdentity, node.ServerIdentity.Public, node.ServerIdentity.ID.String())
			pubKeysMap[node.ServerIdentity.ID.String()] = node.ServerIdentity.Public
		}
		*/

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

		//local.CloseAll()

	}
}

