package main

/*
The simulation-file can be used with the `cothority/simul` and be run either
locally or on deterlab. Contrary to the `test` of the protocol, the simulation
is much more realistic, as it tests the protocol on different nodes, and not
only in a test-environment.

The Setup-method is run once on the client and will create all structures
and slices necessary to the simulation. It also receives a 'dir' argument
of a directory where it can write files. These files will be copied over to
the simulation so that they are available.

The Run-method is called only once by the root-node of the tree defined in
Setup. It should run the simulation in different rounds. It can also
measure the time each run takes.

In the Node-method you can read the files that have been created by the
'Setup'-method.
*/

import (
	//"errors"
	//"strconv"
	"time"
	"fmt"

	"github.com/BurntSushi/toml"
	//"github.com/dedis/cothority_template/protocol"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	//"gopkg.in/dedis/onet.v2/simul/monitor"
	"gopkg.in/dedis/kyber.v2"
	"bls-ftcosi/blsftcosi/protocol"
)

func init() {
	onet.SimulationRegister("BlsFtCosiProtocol", NewSimulationProtocol)
}

// SimulationProtocol implements onet.Simulation.
type SimulationProtocol struct {
	onet.SimulationBFTree
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

var defaultTimeout = 5 * time.Second

// Run implements onet.Simulation.
func (s *SimulationProtocol) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", s.Rounds)
	for round := 0; round < s.Rounds; round++ {
		log.Lvl1("Starting round", round)
		/*
		round := monitor.NewTimeMeasure("round")
		p, err := config.Overlay.CreateProtocol("Template", config.Tree,
			onet.NilServiceID)
		if err != nil {
			return err
		}
		go p.Start()
		children := <-p.(*protocol.TemplateProtocol).ChildCount
		round.Record()
		if children != size {
			return errors.New("Didn't get " + strconv.Itoa(size) +
				" children")
		}
		*/

		nodes :=  []int{4} // []int{1, 2, 5, 13, 24}
		subtrees := []int{1} // []int{1, 2, 5, 9}
		proposal := []byte("dedis") //[]byte{0xFF}

		for _, nNodes := range nodes {
			for _, nSubtrees := range subtrees {
				log.Lvl2("test asking for", nNodes, "nodes and", nSubtrees, "subtrees")

				//local := onet.NewLocalTest(testSuite) // TODO pointer?
				//_, _, tree := local.GenTree(nNodes, false)

				// get public keys
				publics := make([]kyber.Point, config.Tree.Size())
				for i, node := range config.Tree.List() {
					publics[i] = node.ServerIdentity.Public
				}

				pi, err := config.Overlay.CreateProtocol("blsftCoSiProtoDefault", config.Tree, onet.NilServiceID)
				if err != nil {
					//local.CloseAll()
					return err
				}
				cosiProtocol := pi.(*protocol.BlsFtCosi)
				cosiProtocol.CreateProtocol = config.Overlay.CreateProtocol
				cosiProtocol.Msg = proposal
				cosiProtocol.NSubtrees = nSubtrees
				cosiProtocol.Timeout = defaultTimeout

				err = cosiProtocol.Start()
				if err != nil {
					return err
				}

				// get and verify signature
				err = getAndVerifySignature(cosiProtocol, publics, proposal, protocol.CompletePolicy{})
				if err != nil {
					return err
				}

			}
		}

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

	return nil // verifySignature(signature, publics, proposal, policy)
}

/*
func verifySignature(signature []byte, publics []kyber.Point,
	proposal []byte, policy protocol.Policy) error {
	// verify signature

	
	err := protocol.Verify(testSuite, publics, proposal, signature, policy)
	if err != nil {
		return fmt.Errorf("didn't get a valid signature: %s", err)
	}
	
	log.Lvl2("Signature correctly verified!")
	return nil
}
*/