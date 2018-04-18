package protocol


import (

	"fmt"
	"sync"
	"time"
	"github.com/dedis/onet/network"
	"github.com/dedis/onet"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/sign/cosi"
	"github.com/dedis/onet/log" 
)


// VerificationFn is called on every node. Where msg is the message that is
// co-signed and the data is additional data for verification.
type VerificationFn func(msg []byte, data []byte) bool


// init is done at startup. It defines every messages that is handled by the network
// and registers the protocols.
func init() {
	network.RegisterMessages(Challenge{}, Response{}, Stop{})
}


// FtCosi holds the parameters of the protocol.
// It also defines a channel that will receive the final signature.
// This protocol should only exist on the root node.
type BlsFtCosi struct {
	*onet.TreeNodeInstance
	NSubtrees	int
	Msg		[]byte
	Data		[]byte

	Timeout        time.Duration // sub-protocol time out
	FinalSignature chan []byte // finale signature, that is sent back to client

	publics         []kyber.Point // list of public keys
	stoppedOnce     sync.Once 
	startChan       chan bool
	subProtocolName string
	verificationFn  VerificationFn
	suite cosi.Suite
}


// CreateProtocolFunction is a function type which creates a new protocol
// used in FtCosi protocol for creating sub leader protocols.
type CreateProtocolFunction func(name string, t *onet.Tree) (onet.ProtocolInstance, error)

// Shutdown stops the protocol
func (p *BlsFtCosi) Shutdown() error {
	p.stoppedOnce.Do(func() {
		close(p.FinalSignature)
	})
	return nil
}

func (p *BlsFtCosi) Dispatch() error {
	// TODO
	return nil
}


// Start is done only by root and starts the protocol.
// It also verifies that the protocol has been correctly parameterized.
func (p *BlsFtCosi) Start() error {
	if p.Msg == nil {
		close(p.startChan)
		return fmt.Errorf("no proposal msg specified")
	}
	if p.CreateProtocol == nil {
		close(p.startChan)
		return fmt.Errorf("no create protocol function specified")
	}
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


