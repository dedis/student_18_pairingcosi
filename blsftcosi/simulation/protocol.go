package main


import (
	"time"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/simul/monitor"
	"github.com/dedis/kyber"
	"bls-ftcosi/blsftcosi/protocol"
	"github.com/dedis/cothority"
	"github.com/dedis/kyber/pairing"
	"github.com/dedis/kyber/pairing/bn256"
)

func init() {
	onet.SimulationRegister("BlsFtCosiProtocol", NewSimulationProtocol)

	cothority.Suite = struct{
	    pairing.Suite
	    kyber.Group
	}{
	    Suite: bn256.NewSuite(),
	    Group: bn256.NewSuiteG2(),
	}
}

// SimulationProtocol implements onet.Simulation.
type SimulationProtocol struct {
	onet.SimulationBFTree
	NNodes				int
	NSubtrees			int
	FailingSubleaders	int
	FailingLeafs		int
}

// NewSimulationProtocol is used internally to register the simulation (see the init()
// function above).
func NewSimulationProtocol(config string) (onet.Simulation, error) {
	es := &SimulationProtocol{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup implements onet.Simulation.
func (s *SimulationProtocol) Setup(dir string, hosts []string) (
	*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

// Node can be used to initialize each node before it will be run
// by the server. Here we call the 'Node'-method of the
// SimulationBFTree structure which will load the roster- and the
// tree-structure to speed up the first round.
func (s *SimulationProtocol) Node(config *onet.SimulationConfig) error {
	index, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}
	log.Lvl3("Initializing node-index", index)
	return s.SimulationBFTree.Node(config)
}

var defaultTimeout = 30 * time.Second
var proposal = []byte("dedis")

// Run implements onet.Simulation.
func (s *SimulationProtocol) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	thold := size * 2 / 3
	log.Lvl1("Size is:", size, "rounds:", s.Rounds)
	log.Lvl1("Simulating for", s.Hosts, "nodes and", s.NSubtrees, "subtrees in ", s.Rounds, "round")
	for round := 0; round < s.Rounds; round++ {

		roundNoVerify := monitor.NewTimeMeasure("roundNoVerify")
		fullRound := monitor.NewTimeMeasure("fullRound")

		// get public keys
		publics := make([]kyber.Point, config.Tree.Size())
		for i, node := range config.Tree.List() {
			publics[i] = node.ServerIdentity.Public
		}

		pi, err := config.Overlay.CreateProtocol("blsftCoSiProtoDefault", config.Tree, onet.NilServiceID)
		if err != nil {
			return err
		}
		cosiProtocol := pi.(*protocol.BlsFtCosi)
		cosiProtocol.CreateProtocol = config.Overlay.CreateProtocol
		cosiProtocol.Msg = proposal
		cosiProtocol.NSubtrees = s.NSubtrees
		cosiProtocol.Timeout = defaultTimeout

		err = cosiProtocol.Start()
		if err != nil {
			return err
		}

		var signature []byte
		select {
		case signature = <-cosiProtocol.FinalSignature:
			log.Lvl3("Instance is done")
			roundNoVerify.Record()
		case <-time.After(defaultTimeout * 2):
			// wait a bit longer than the protocol timeout
			return fmt.Errorf("didn't get commitment in time")
		}

		
		verificationOnly := monitor.NewTimeMeasure("verificationOnly")
		err = verifySignature(cosiProtocol.PairingSuite, signature, publics, proposal, protocol.NewThresholdPolicy(thold))
		if err != nil {
			return err
		}
		verificationOnly.Record()

		fullRound.Record()
	}

	return nil
}

func getAndVerifySignature(cosiProtocol *protocol.BlsFtCosi, publics []kyber.Point,
	proposal []byte, policy protocol.Policy) error {
	var signature []byte
	select {
	case signature = <-cosiProtocol.FinalSignature:
		log.Lvl3("Instance is done")
		_ = signature
	case <-time.After(defaultTimeout * 2):
		// wait a bit longer than the protocol timeout
		return fmt.Errorf("didn't get commitment in time")
	}

	return verifySignature(cosiProtocol.PairingSuite, signature, publics, proposal, policy)
}


func verifySignature(ps pairing.Suite, signature []byte, publics []kyber.Point, proposal []byte, policy protocol.Policy) error {
	// verify signature

	
	err := protocol.Verify(ps, publics, proposal, signature, policy)
	if err != nil {
		return fmt.Errorf("didn't get a valid signature: %s", err)
	}
	
	log.Lvl2("Signature correctly verified!")
	return nil
}
