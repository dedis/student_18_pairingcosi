
package protocol

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/kyber/pairing"
	"github.com/dedis/kyber/pairing/bn256"
)

// sub_protocol is run by each sub-leader and each node once, and n times by 
// the root leader, where n is the number of sub-leader.


// SubFtCosi holds the different channels used to receive the different protocol messages.
type SubBlsFtCosi struct {
	*onet.TreeNodeInstance
	Publics        []kyber.Point
	Msg            []byte
	Data           []byte
	
	Timeout        time.Duration
	stoppedOnce    sync.Once
	verificationFn VerificationFn
	pairingSuite   pairing.Suite

	// protocol/subprotocol channels
	// these are used to communicate between the subprotocol and the main protocol
	subleaderNotResponding chan bool
	subResponse            chan StructResponse

	// internodes channels
	ChannelChallenge    chan StructChallenge
	ChannelResponse     chan StructResponse
}


func init() {
	GlobalRegisterDefaultProtocols()
}

// NewDefaultSubProtocol is the default sub-protocol function used for registration
// with an always-true verification.
func NewDefaultSubProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	vf := func(a, b []byte) bool { return true }
	return NewSubBlsFtCosi(n, vf, bn256.NewSuite())
}

// NewSubFtCosi is used to define the subprotocol and to register
// the channels where the messages will be received.
func NewSubBlsFtCosi(n *onet.TreeNodeInstance, vf VerificationFn, pairingSuite pairing.Suite) (onet.ProtocolInstance, error) {

	c := &SubBlsFtCosi{
		TreeNodeInstance: n,
		verificationFn:   vf,
		pairingSuite:     pairingSuite,
	}

	if n.IsRoot() {
		c.subleaderNotResponding = make(chan bool)
		c.subResponse = make(chan StructResponse)
	}

	for _, channel := range []interface{}{
		&c.ChannelChallenge,
		&c.ChannelResponse,
	} {
		err := c.RegisterChannel(channel)
		if err != nil {
			return nil, errors.New("couldn't register channel: " + err.Error())
		}
	}
	err := c.RegisterHandler(c.HandleStop)
	if err != nil {
		return nil, errors.New("couldn't register stop handler: " + err.Error())
	}
	return c, nil
}




// Shutdown stops the protocol
func (p *SubBlsFtCosi) Shutdown() error {
	p.stoppedOnce.Do(func() {
		close(p.ChannelChallenge)
		close(p.ChannelResponse)
	})
	return nil
}

// Dispatch is the main method of the subprotocol, running on each node and handling the messages in order
func (p *SubBlsFtCosi) Dispatch() error {
	defer p.Done()

	// TODO verification of Data


	// ----- Challenge -----
	challenge, channelOpen := <-p.ChannelChallenge // From
	if !channelOpen {
		return nil
	}

	log.Lvl3(p.ServerIdentity().Address, "received 'challenge' ")
	p.Msg = challenge.Msg
	p.Data = challenge.Data
	p.Publics = challenge.Publics
	p.Timeout = challenge.Timeout
	//var err error

	// TODO don't understand this
	//if errs := p.Multicast(&challenge.Challenge, committedChildren...); len(errs) > 0 {
	//	log.Lvl3(p.ServerIdentity().Address, "")
	//}

	// Timeout is shorter than root protocol because itself waits on this
	t := time.After(p.Timeout / 2)

	// Collect all responses from children, store them and wait till all have responded or timed out.
	responses := make([]StructResponse, 0)
loop:
	// note that this section will not execute if it's on a leaf
	for range p.Children() {
		select {
			case response, channelOpen := <-p.ChannelResponse:
			if !channelOpen {
				return nil
			}
			responses = append(responses, response)
		case <-t:
			break loop
		}
	}

	// TODO
	ok := true

	if p.IsRoot() {
		// send response to super-protocol
		if len(responses) != 1 {
			return fmt.Errorf(
				"root node in subprotocol should have received 1 signature response, but received %v",
				len(responses))
		}
		p.subResponse <- responses[0]
	} else {
		// Generate own signature and aggregate with all children signatures
		signaturePoint, err := generateSignature(p.pairingSuite, p.TreeNodeInstance, responses, p.Msg, ok)
		if err != nil {
			return err
		}
		err = p.SendToParent(&Response{signaturePoint})
		if err != nil {
			return err
		}
	}

	return nil
}

// Start is done only by root and starts the subprotocol
func (p *SubBlsFtCosi) Start() error {
	log.Lvl3(p.ServerIdentity().Address, "Starting subCoSi")
	if p.Msg == nil {
		return errors.New("subprotocol does not have a proposal msg")
	}
	if p.Data == nil {
		return errors.New("subprotocol does not have data, it can be empty but cannot be nil")
	}
	if p.Publics == nil || len(p.Publics) < 1 {
		return errors.New("subprotocol has invalid public keys")
	}
	if p.verificationFn == nil {
		return errors.New("subprotocol has an empty verification fn")
	}
	if p.Timeout < 10*time.Nanosecond {
		return errors.New("unrealistic timeout")
	}

	challenge := StructChallenge{
		p.TreeNode(),
		Challenge{p.Msg, p.Data, p.Publics, p.Timeout},
	}
	p.ChannelChallenge <- challenge
	return nil
}


// HandleStop is called when a Stop message is send to this node.
// It broadcasts the message to all the nodes in tree and each node will stop
// the protocol by calling p.Done.
func (p *SubBlsFtCosi) HandleStop(stop StructStop) error {
	defer p.Done()
	if p.IsRoot() {
		p.Broadcast(&stop.Stop)
	}
	return nil
}