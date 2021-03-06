package protocol

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/kyber/pairing"
	//"github.com/stretchr/testify/require"

)


const FailureProtocolName = "FailureProtocol"
const FailureSubProtocolName = "FailureSubProtocol"

const RefuseOneProtocolName = "RefuseOneProtocol"
const RefuseOneSubProtocolName = "RefuseOneSubProtocol"

func init() {
	log.SetDebugVisible(1)
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

type NetworkSuite struct {
    kyber.Group
    pairing.Suite
}


func NewNetworkSuite(pairingSuite pairing.Suite) *NetworkSuite {
    return &NetworkSuite{
        Group: pairingSuite.G2(),
        Suite: pairingSuite,
    }
}

var testSuite = *NewNetworkSuite(ThePairingSuite)
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
	// TODO doesn't work with 1 subtree and 5 or more nodes (works for 1 to 4 nodes)
	nodes :=  []int{24} // []int{1, 2, 5, 13, 24}
	subtrees := []int{1} // []int{1, 2, 5, 9}
	proposal := []byte("dedis") //[]byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			log.Lvl2("test asking for", nNodes, "nodes and", nSubtrees, "subtrees")

			local := onet.NewLocalTest(testSuite) // TODO pointer?
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
			err = getAndVerifySignature(cosiProtocol, publics, proposal, CompletePolicy{})
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			local.CloseAll()
		}
	}
}



// Tests unresponsive leaves in various tree configurations
func TestUnresponsiveLeafs(t *testing.T) {
	nodes := []int{3, 13, 24}
	subtrees := []int{1, 2}
	proposal := []byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			log.Lvl2("test asking for", nNodes, "nodes and", nSubtrees, "subtrees")

			local := onet.NewLocalTest(testSuite)
			servers, roster, tree := local.GenTree(nNodes, false)
			require.NotNil(t, roster)

			// get public keys
			publics := make([]kyber.Point, tree.Size())
			for i, node := range tree.List() {
				publics[i] = node.ServerIdentity.Public
			}

			// create protocol
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

			// find first subtree leaves servers based on GenTree function
			leafsServerIdentities, err := GetLeafsIDs(tree, nNodes, nSubtrees)
			if err != nil {
				t.Fatal(err)
			}
			failing := (len(leafsServerIdentities) - 1) / 3 // we render unresponsive one third of leafs
			failingLeafsServerIdentities := leafsServerIdentities[:failing]
			firstLeavesServers := make([]*onet.Server, 0)
			for _, s := range servers {
				for _, l := range failingLeafsServerIdentities {
					if s.ServerIdentity.ID == l {
						firstLeavesServers = append(firstLeavesServers, s)
						break
					}
				}
			}

			// pause the router for the faulty servers
			for _, l := range firstLeavesServers {
				l.Pause()
			}

			// start protocol
			err = cosiProtocol.Start()
			if err != nil {
				local.CloseAll()
				t.Fatal("error in starting of protocol:", err)
			}

			// get and verify signature
			threshold := nNodes - failing
			err = getAndVerifySignature(cosiProtocol, publics, proposal, NewThresholdPolicy(threshold))
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			local.CloseAll()
		}
	}
}



// Tests unresponsive subleaders in various tree configurations
func TestUnresponsiveSubleader(t *testing.T) {
	nodes := []int{6, 13, 24}
	subtrees := []int{1, 2}
	proposal := []byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			log.Lvl2("test asking for", nNodes, "nodes and", nSubtrees, "subtrees")

			local := onet.NewLocalTest(testSuite)
			servers, _, tree := local.GenTree(nNodes, false)

			// get public keys
			publics := make([]kyber.Point, tree.Size())
			for i, node := range tree.List() {
				publics[i] = node.ServerIdentity.Public
			}

			// create protocol
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

			// find first subleader server based on genTree function
			subleaderIds, err := GetSubleaderIDs(tree, nNodes, nSubtrees)
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			} else if len(subleaderIds) < 1 {
				local.CloseAll()
				t.Fatal("found no subleader in generated tree with ", nNodes, "nodes and", nSubtrees, "subtrees")
			}
			var firstSubleaderServer *onet.Server
			for _, s := range servers {
				if s.ServerIdentity.ID == subleaderIds[0] {
					firstSubleaderServer = s
					break
				}
			}

			// pause the first sub leader to simulate failure
			firstSubleaderServer.Pause()

			// start protocol
			err = cosiProtocol.Start()
			if err != nil {
				local.CloseAll()
				t.Fatal("Error in starting of protocol:", err)
			}

			// get and verify signature
			err = getAndVerifySignature(cosiProtocol, publics, proposal, NewThresholdPolicy(nNodes-1))
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			local.CloseAll()
		}
	}
}



// Tests that the protocol throws errors with invalid configurations
func TestProtocolErrors(t *testing.T) {
	nodes := []int{1, 2, 5, 13, 24}
	subtrees := []int{1, 2, 5}
	proposal := []byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			log.Lvl2("test asking for", nNodes, "nodes and", nSubtrees, "subtrees")

			local := onet.NewLocalTest(testSuite)
			_, _, tree := local.GenTree(nNodes, false)

			// missing create protocol function
			pi, err := local.CreateProtocol(DefaultProtocolName, tree)
			if err != nil {
				local.CloseAll()
				t.Fatal("Error in creation of protocol:", err)
			}
			cosiProtocol := pi.(*BlsFtCosi)
			//cosiProtocol.CreateProtocol = local.CreateProtocol
			cosiProtocol.Msg = proposal
			cosiProtocol.NSubtrees = nSubtrees
			cosiProtocol.Timeout = defaultTimeout

			err = cosiProtocol.Start()
			if err == nil {
				local.CloseAll()
				t.Fatal("protocol should throw an error if called without create protocol function, but doesn't")
			}

			// missing proposal
			pi, err = local.CreateProtocol(DefaultProtocolName, tree)
			if err != nil {
				local.CloseAll()
				t.Fatal("Error in creation of protocol:", err)
			}
			cosiProtocol = pi.(*BlsFtCosi)
			cosiProtocol.CreateProtocol = local.CreateProtocol
			//cosiProtocol.Msg = proposal
			cosiProtocol.NSubtrees = nSubtrees
			cosiProtocol.Timeout = defaultTimeout

			err = cosiProtocol.Start()
			if err == nil {
				local.CloseAll()
				t.Fatal("protocol should throw an error if called without a proposal, but doesn't")
			}

			local.CloseAll()
		}
	}
}


func TestProtocolRefusalAll(t *testing.T) {
	// TODO with 4 nodes passes, with 5 nodes and 1 subtree fails! (i.e. when there are 3 brother leaves)
	nodes :=  []int{4, 5, 13}
	subtrees :=   []int{1, 2, 5, 9}
	proposal := []byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			log.Lvl1("test asking for", nNodes, "nodes and", nSubtrees, "subtrees")

			local := onet.NewLocalTest(testSuite)
			_, _, tree := local.GenTree(nNodes, false)

			// get public keys
			publics := make([]kyber.Point, tree.Size())
			for i, node := range tree.List() {
				publics[i] = node.ServerIdentity.Public
			}

			pi, err := local.CreateProtocol(FailureProtocolName, tree)
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

			// only the leader agrees, the verification should only pass with a threshold of 1
			// the rest, including using the complete policy should fail
			var signature []byte
			select {
			case signature = <-cosiProtocol.FinalSignature:
				log.Lvl3("Instance is done")
			case <-time.After(defaultTimeout * 4):
				// wait a bit longer than the protocol timeout
				local.CloseAll()
				t.Fatal("didn't get commitment in time")
			}

			err = verifySignature(signature, publics, proposal, CompletePolicy{})
			if err == nil {
				local.CloseAll()
				t.Fatal("verification should fail")
			}

			err = verifySignature(signature, publics, proposal, NewThresholdPolicy(2))
			if err == nil {
				local.CloseAll()
				t.Fatal("verification should fail")
			}

			err = verifySignature(signature, publics, proposal, NewThresholdPolicy(1))
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			local.CloseAll()
		}
	}
}



func getAndVerifySignature(cosiProtocol *BlsFtCosi, publics []kyber.Point,
	proposal []byte, policy Policy) error {
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
	proposal []byte, policy Policy) error {
	// verify signature

	
	err := Verify(testSuite, publics, proposal, signature, policy)
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