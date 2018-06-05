package protocol

/*
The test-file should at the very least run the protocol for a varying number
of nodes. It is even better practice to test the different methods of the
protocol, as in Test Driven Development.
*/

import (
	"testing"
	"time"

	//"github.com/dedis/cothority_template/protocol"
	"gopkg.in/dedis/kyber.v2/suites"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
)

var tSuite = suites.MustFind("Ed25519")
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
	nodes := []int{5} // []int{2, 5, 13}

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

		time.Sleep(time.Second *3)


		//timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*nbrNodes*2) * time.Millisecond
		/*
		select {
		case children := <-protocol.ChildCount:
			log.Lvl2("Instance 1 is done")
			require.Equal(t, children, nbrNodes, "Didn't get a child-cound of", nbrNodes)
		case <-time.After(timeout):
			t.Fatal("Didn't finish in time")
		}
		*/
		local.CloseAll()
	}
}

