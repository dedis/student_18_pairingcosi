package protocol

import (
	//"flag"
	"fmt"
	"sync"
	"testing"
	"time"

	//"github.com/dedis/cothority"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/sign/cosi"
	"bls-ftcosi/onet"
	"bls-ftcosi/onet/log"
	//"github.com/stretchr/testify/require"
	"github.com/dedis/kyber/pairing/bn256"
	//"github.com/dedis/kyber/pairing"


)




const FailureProtocolName = "FailureProtocol"
const FailureSubProtocolName = "FailureSubProtocol"

const RefuseOneProtocolName = "RefuseOneProtocol"
const RefuseOneSubProtocolName = "RefuseOneSubProtocol"

func init() {
	log.SetDebugVisible(3)
	GlobalRegisterDefaultProtocols()
	onet.GlobalProtocolRegister(FailureProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		vf := func(a, b []byte) bool { return true }
		return NewBlsFtCosi(n, vf, FailureSubProtocolName, testSuite)
	})
	onet.GlobalProtocolRegister(FailureSubProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		vf := func(a, b []byte) bool { return false }
		return NewSubBlsFtCosi(n, vf, testSuite)
	})
	onet.GlobalProtocolRegister(RefuseOneProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		vf := func(a, b []byte) bool { return true }
		return NewBlsFtCosi(n, vf, RefuseOneSubProtocolName, testSuite)
	})
	onet.GlobalProtocolRegister(RefuseOneSubProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewSubBlsFtCosi(n, refuse, testSuite)
	})
}

var testSuite = onet.NewNetworkSuite(bn256.NewSuite())
var defaultTimeout = 5 * time.Second
/*
func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		defaultTimeout = 20 * time.Second
	}
	log.MainTest(m)
}
*/
// Tests various trees configurations
func TestProtocol(t *testing.T) {
	nodes := []int{2} // []int{1, 2, 5, 13, 24}
	subtrees := []int{1} //  []int{1, 2, 5, 9}
	proposal := []byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			log.Lvl2("test asking for", nNodes, "nodes and", nSubtrees, "subtrees")

			local := onet.NewLocalTest(*testSuite) // TODO pointer?
			_, _, tree := local.GenTree(nNodes, false)

			// get public keys
			publics := make([]kyber.Point, tree.Size())
			for i, node := range tree.List() {
				publics[i] = node.ServerIdentity.Public
			}

			pi, err := local.CreateProtocol(DefaultProtocolName, tree)
			if err != nil {
				local.CloseAll()
				t.Fatal("Error in creation of protocol:", err)
			}
			cosiProtocol := pi.(*BlsFtCosi)
			cosiProtocol.CreateProtocol = local.CreateProtocol
			cosiProtocol.Msg = proposal
			cosiProtocol.NSubtrees = nSubtrees
			cosiProtocol.Timeout = defaultTimeout

			err = cosiProtocol.Start()
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			// get and verify signature
			err = getAndVerifySignature(cosiProtocol, publics, proposal, cosi.CompletePolicy{})
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			local.CloseAll()
		}
	}
}

func getAndVerifySignature(cosiProtocol *BlsFtCosi, publics []kyber.Point,
	proposal []byte, policy cosi.Policy) error {
	var signature []byte
	select {
	case signature = <-cosiProtocol.FinalSignature:
		log.Lvl3("Instance is done")
	case <-time.After(defaultTimeout * 2):
		// wait a bit longer than the protocol timeout
		return fmt.Errorf("didn't get commitment in time")
	}

	return verifySignature(signature, publics, proposal, policy)
}

func verifySignature(signature []byte, publics []kyber.Point,
	proposal []byte, policy cosi.Policy) error {
	// verify signature
	
	err := Verify(testSuite, publics, proposal, signature)
	if err != nil {
		return fmt.Errorf("didn't get a valid signature: %s", err)
	}
	
	log.Lvl2("Signature correctly verified!")
	return nil
}



type Counter struct {
	veriCount int
	refuseIdx int
	sync.Mutex
}

var counter = &Counter{}


func refuse(msg, data []byte) bool {
	counter.Lock()
	defer counter.Unlock()
	defer func() { counter.veriCount++ }()
	if counter.veriCount == counter.refuseIdx {
		return false
	}
	return true
}