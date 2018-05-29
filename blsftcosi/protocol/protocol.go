package protocol

import (
	"fmt"
	"sync"
	"time"
	"bls-ftcosi/onet/network"
	"bls-ftcosi/onet"
	"github.com/dedis/kyber"
	"bls-ftcosi/onet/log"
	"github.com/dedis/kyber/pairing"
	"github.com/dedis/kyber/pairing/bn256"

	//"reflect"
	"errors"
	
)


// VerificationFn is called on every node. Where msg is the message that is
// co-signed and the data is additional data for verification.
type VerificationFn func(msg []byte, data []byte) bool


// init is done at startup. It defines every messages that is handled by the network
// and registers the protocols.
func init() {
	network.RegisterMessages(Announcement{}, Response{}, Stop{}, Dummy{})
}


// BlsFtCosi holds the parameters of the protocol.
// It also defines a channel that will receive the final signature.
// This protocol should only exist on the root node.
type BlsFtCosi struct {
	*onet.TreeNodeInstance
	NSubtrees	int
	Msg			[]byte
	Data		[]byte
	CreateProtocol CreateProtocolFunction

	Timeout        time.Duration // sub-protocol time out
	FinalSignature chan []byte // final signature that is sent back to client

	publics         []kyber.Point // list of public keys
	stoppedOnce     sync.Once 
	startChan       chan bool
	subProtocolName string
	verificationFn  VerificationFn
	pairingSuite 	pairing.Suite
	dummyChannel 	chan StructDummy
}


// CreateProtocolFunction is a function type which creates a new protocol
// used in FtCosi protocol for creating sub leader protocols.
type CreateProtocolFunction func(name string, t *onet.Tree) (onet.ProtocolInstance, error)


// NewFtCosi method is used to define the ftcosi protocol.
// Called by NewDefaultProtocol
func NewBlsFtCosi(n *onet.TreeNodeInstance, vf VerificationFn, subProtocolName string, pairingSuite pairing.Suite) (onet.ProtocolInstance, error) {

	var list []kyber.Point
	for _, t := range n.Tree().List() {
		list = append(list, t.ServerIdentity.Public)
	}

	c := &BlsFtCosi{
		TreeNodeInstance: n,
		FinalSignature:   make(chan []byte, 1),
		Data:             make([]byte, 0),
		publics:          list,
		startChan:        make(chan bool, 1),
		verificationFn:   vf,
		subProtocolName:  subProtocolName,
		pairingSuite:     pairingSuite,
		dummyChannel:	  make(chan StructDummy),
	}




	err := c.RegisterChannel(c.dummyChannel)
	if err != nil {
		return nil, errors.New("couldn't register channel: " + err.Error())
	}
	

	return c, nil
}

var ThePairingSuite = bn256.NewSuite()

// NewDefaultProtocol is the default protocol function used for registration
// with an always-true verification.
// Called by GlobalRegisterDefaultProtocols
func NewDefaultProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	vf := func(a, b []byte) bool { return true }
	return NewBlsFtCosi(n, vf, DefaultSubProtocolName, ThePairingSuite)
}


// GlobalRegisterDefaultProtocols is used to register the protocols before use,
// most likely in an init function.
func GlobalRegisterDefaultProtocols() {
	onet.GlobalProtocolRegister(DefaultProtocolName, NewDefaultProtocol)
	onet.GlobalProtocolRegister(DefaultSubProtocolName, NewDefaultSubProtocol)
}

	

// Shutdown stops the protocol
func (p *BlsFtCosi) Shutdown() error {
	p.stoppedOnce.Do(func() {
		close(p.FinalSignature)
	})
	return nil
}

func (p *BlsFtCosi) Dispatch() error {
	
	defer p.Done()
	log.Lvl1("this is 1 protocol")

	if p.IsRoot() {
		//log.Lvl1(p.Tree().Size())
		p.SendToChildren(&Dummy{DummyMsg:[]byte("msg")})
		
	} else {
		<- p.dummyChannel
		log.Lvl1("read message")
	}

	return nil
	

	/*
	defer p.Done()

	// if node is not root, doesn't use protocol but sub-protocol
	if !p.IsRoot() {
		return nil
	}

	select {
		case _, ok := <-p.startChan:
			if !ok {
				log.Lvl1("protocol finished prematurely")
				return nil
			}
			close(p.startChan)
		case <-time.After(time.Second):
			return fmt.Errorf("timeout, did you forget to call Start?")
	}

	log.Lvl3("leader protocol started")

	// Verification of the data
	verifyChan := make(chan bool, 1)
	go func() {
		log.Lvl3(p.ServerIdentity().Address, "starting verification")
		verifyChan <- p.verificationFn(p.Msg, p.Data)
	}()

	// generate trees
	nNodes := p.Tree().Size()
	trees, err := genTrees(p.Tree().Roster, nNodes, p.NSubtrees)
	if err != nil {
		return fmt.Errorf("error in tree generation: %s", err)
	}

	// if one node, sign without subprotocols
	if nNodes == 1 {
		trees = make([]*onet.Tree, 0)
	}

	// start all subprotocols
	cosiSubProtocols := make([]*SubBlsFtCosi, len(trees))
	for i, tree := range trees {
		cosiSubProtocols[i], err = p.startSubProtocol(tree)
		if err != nil {
			return err
		}
	}
	log.Lvl3(p.ServerIdentity().Address, "all protocols started")

	// Wait and collect all the signature responses
	responses, runningSubProtocols, err := p.collectSignatures(trees, cosiSubProtocols)
	if err != nil {
		return err
	}
	log.Lvl3(p.ServerIdentity().Address, "BBBBBBBBBBBBBBBBBBBBB collected all signature responses")


	_ = runningSubProtocols

	// TODO
	ok := true

	// generate root signature
	signaturePoint, finalMask, err := generateSignature(p.pairingSuite, p.TreeNodeInstance, p.publics, responses, p.Msg, ok)
	if err != nil {
		return err
	}

	signature, err := signaturePoint.MarshalBinary()
	if err != nil {
		return err
	}
	// TODO bit mask
	// TODO create signature with appended mask
	finalSignature := AppendSigAndMask(signature, finalMask)

	//fmt.Println("xxx 1", reflect.TypeOf(finalSignature), finalSignature)

	log.Lvl3(p.ServerIdentity().Address, "Created final signature")

	p.FinalSignature <- finalSignature

	//fmt.Println("xxx 2")

	log.Lvl3("Root-node is done without errors")

	return nil
	*/
	
}

// Collect signatures from each sub-leader, restart whereever sub-leaders fail to respond.
// The collected signatures are already aggregated for a particular group
func (p *BlsFtCosi) collectSignatures(trees []*onet.Tree, cosiSubProtocols []*SubBlsFtCosi) ([]StructResponse, []*SubBlsFtCosi, error) {

	var mut sync.Mutex
	var wg sync.WaitGroup
	errChan := make(chan error, len(cosiSubProtocols))
	responses := make([]StructResponse, 0)
	runningSubProtocols := make([]*SubBlsFtCosi, 0)


	/////

	for i, subProtocol := range cosiSubProtocols {
		log.Lvl3("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc", i)

		wg.Add(1)
		go func(i int, subProtocol *SubBlsFtCosi) {
			defer wg.Done()
			for {
				select {
				case <-subProtocol.subleaderNotResponding: // TODO need to modify not reponsing step?
					subleaderID := trees[i].Root.Children[0].RosterIndex
					log.Lvlf2("subleader from tree %d (id %d) failed, restarting it", i, subleaderID)

					// send stop signal
					subProtocol.HandleStop(StructStop{subProtocol.TreeNode(), Stop{}})

					// generate new tree
					newSubleaderID := subleaderID + 1
					if newSubleaderID >= len(trees[i].Roster.List) {
						log.Lvl2("subprotocol", i, "failed with every subleader, ignoring this subtree")
						return
					}
					var err error
					trees[i], err = genSubtree(trees[i].Roster, newSubleaderID)
					if err != nil {
						errChan <- fmt.Errorf("(node %v) %v", i, err)
						return
					}

					// restart subprotocol
					subProtocol, err = p.startSubProtocol(trees[i])
					if err != nil {
						err = fmt.Errorf("(node %v) error in restarting of subprotocol: %s", i, err)
						errChan <- err
						return
					}
					mut.Lock()
					cosiSubProtocols[i] = subProtocol
					mut.Unlock()
				case response := <-subProtocol.subResponse:
					log.Lvl2("AAAAA leader received one response")

					mut.Lock()
					runningSubProtocols = append(runningSubProtocols, subProtocol)
					responses = append(responses, response)
					mut.Unlock()
					return
				case <-time.After(p.Timeout):
					err := fmt.Errorf("(node %v) didn't get response after timeout %v", i, p.Timeout)
					errChan <- err
					return
				}
			}
		}(i, subProtocol)
	}
	wg.Wait()

	close(errChan)
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return nil, nil, fmt.Errorf("failed to collect responses with errors %v", errs)
	}

	///////////////////

	return responses, runningSubProtocols, nil
}

// Start is done only by root and starts the protocol.
// It also verifies that the protocol has been correctly parameterized.
func (p *BlsFtCosi) Start() error {
	if p.Msg == nil {
		close(p.startChan)
		return fmt.Errorf("no proposal msg specified")
	}
	// TODO compile says always False
	//if p.CreateProtocol == nil {
	//	close(p.startChan)
	//	return fmt.Errorf("no create protocol function specified")
	//}
	if p.verificationFn == nil {
		close(p.startChan)
		return fmt.Errorf("verification function cannot be nil")
	}
	if p.subProtocolName == "" {
		close(p.startChan)
		return fmt.Errorf("sub-protocol name cannot be empty")
	}
	if p.Timeout < 10 {
		close(p.startChan)
		return fmt.Errorf("unrealistic timeout")
	}

	if p.NSubtrees < 1 {
		p.NSubtrees = 1
	}

	log.Lvl3("Starting CoSi")
	p.startChan <- true
	return nil
}

// startSubProtocol creates, parametrize and starts a subprotocol on a given tree
// and returns the started protocol.
func (p *BlsFtCosi) startSubProtocol(tree *onet.Tree) (*SubBlsFtCosi, error) {

	pi, err := p.CreateProtocol(p.subProtocolName, tree)
	if err != nil {
		return nil, err
	}

	cosiSubProtocol := pi.(*SubBlsFtCosi)
	cosiSubProtocol.Publics = p.publics
	cosiSubProtocol.Msg = p.Msg
	cosiSubProtocol.Data = p.Data
	cosiSubProtocol.Timeout = p.Timeout / 2

	err = cosiSubProtocol.Start()
	if err != nil {
		return nil, err
	}

	return cosiSubProtocol, err
}


