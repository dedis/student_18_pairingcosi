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
	"errors"

	"github.com/BurntSushi/toml"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/simul/monitor"
	"bls-ftcosi/pbft/protocol"
	"bls-ftcosi/cothority/protocols/byzcoin/blockchain"
	"bls-ftcosi/cothority/protocols/byzcoin/blockchain/blkparser"
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

var magicNum = [4]byte{0xF9, 0xBE, 0xB4, 0xD9}
var blocksPath = "/users/csbenz/blocks" // "/home/christo/.bitcoin/blocks"
const ReadFirstNBlocks = 66000
var wantednTxs = 10000

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

func loadBlocks() ([]blkparser.Tx, error) {
	// Initialize blockchain parser
	parser, err := blockchain.NewParser(blocksPath, magicNum)
	_ = parser
	if err != nil {
		return nil, err
	}

	transactions, err := parser.Parse(0, ReadFirstNBlocks)
	if len(transactions) == 0 {
		return nil, errors.New("Couldn't read any transactions.")
	}
	if err != nil {
		log.Error("Error: Couldn't parse blocks in", blocksPath,
			".\nPlease download bitcoin blocks as .dat files first and place them in",
			blocksPath, "Either run a bitcoin node (recommended) or using a torrent.")
		return nil, err
	}
	log.Lvl1("Got", len(transactions), "transactions")
	if len(transactions) < wantednTxs {
		log.Errorf("Read only %v but wanted %v", len(transactions), wantednTxs)
	}

	return transactions, nil
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
var defaultTimeout = 120 * time.Second

// Run implements onet.Simulation.
func (s *SimulationProtocol) Run(config *onet.SimulationConfig) error {
	log.SetDebugVisible(1)

	transactions, err := loadBlocks()
	if err != nil {
		return err
	}

	log.Lvl1("Run got", len(transactions), "transactions")
	
	block, err := GetBlock(3000, transactions, "0", "0", 0)
	if err != nil {
		return err
	}
	binaryBlock, err := block.MarshalBinary()
	if err != nil {
		return err
	}

	size := config.Tree.Size()
	log.Lvl1("Size is:", size, "rounds:", s.Rounds)
	log.Lvl1("Simulating for", s.Hosts, "nodes in ", s.Rounds, "round")

	for round := 0; round < s.Rounds; round++ {
		log.Lvl1("Starting round", round)
		fullRound := monitor.NewTimeMeasure("fullRound")

		pi, err := config.Overlay.CreateProtocol(protocol.DefaultProtocolName, config.Tree, onet.NilServiceID)
		if err != nil {
			return err
		}

		pbftPprotocol := pi.(*protocol.PbftProtocol)
		pbftPprotocol.Msg = binaryBlock
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

		fullRound.Record()
	}
	return nil
}


// GetBlock returns the next block available from the transaction pool.
func GetBlock(size int, transactions []blkparser.Tx, lastBlock string, lastKeyBlock string, priority int) (*blockchain.TrBlock, error) {
	if len(transactions) < 1 {
		return nil, errors.New("no transaction available")
	}

	trlist := blockchain.NewTransactionList(transactions, size)
	header := blockchain.NewHeader(trlist, lastBlock, lastKeyBlock)
	trblock := blockchain.NewTrBlock(trlist, header)
	return trblock, nil
}
