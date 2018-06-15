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
	"fmt"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	//"github.com/dedis/onet/simul/monitor"
	"bls-ftcosi/pbft/protocol"
)

func init() {
	onet.SimulationRegister("PBFTProtocol", NewSimulationProtocol)
}

// SimulationProtocol implements onet.Simulation.
type SimulationProtocol struct {
	onet.SimulationBFTree
	NNodes				int
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

var proposal = []byte("dedis")
var defaultTimeout = 30 * time.Second

// Run implements onet.Simulation.
func (s *SimulationProtocol) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	log.Lvl1("Size is:", size, "rounds:", s.Rounds)
	log.Lvl1("Simulating for", s.Hosts, "nodes in ", s.Rounds, "round")

	for round := 0; round < s.Rounds; round++ {
		log.Lvl1("Starting round", round)
		//round := monitor.NewTimeMeasure("round")

		pi, err := config.Overlay.CreateProtocol("PBFTProtocol", config.Tree, onet.NilServiceID)
		if err != nil {
			return err
		}

		pbftPprotocol := pi.(*protocol.PbftProtocol)
		pbftPprotocol.Msg = proposal
		pbftPprotocol.Timeout = defaultTimeout

		err = pbftPprotocol.Start()
		if err != nil {
			return err
		}

		select {
		case finalReply := <-pbftPprotocol.FinalReply:
			log.Lvl1("Leader sent final reply")
			_ = finalReply
		case <-time.After(defaultTimeout * 2):
			fmt.Errorf("Leader never got enough final replies, timed out")
		}

		//round.Record()
	}
	return nil
}
