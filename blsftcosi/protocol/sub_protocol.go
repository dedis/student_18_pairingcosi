
package protocol

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/kyber.v2/pairing"
	"gopkg.in/dedis/kyber.v2/pairing/bn256"

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
	ChannelAnnouncement   chan StructAnnouncement
	ChannelResponse       chan StructResponse
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
		&c.ChannelAnnouncement,
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
		close(p.ChannelAnnouncement)
		close(p.ChannelResponse)
	})
	return nil
}

// Dispatch is the main method of the subprotocol, running on each node and handling the messages in order
func (p *SubBlsFtCosi) Dispatch() error {
	defer p.Done()

	// TODO verification of Data


	// ----- announcement -----
	announcement, channelOpen := <-p.ChannelAnnouncement // From
	if !channelOpen {
		return nil
	}

	log.Lvl3(p.ServerIdentity().Address, "received annoucement ")
	p.Msg = announcement.Msg
	p.Data = announcement.Data
	p.Publics = announcement.Publics
	p.Timeout = announcement.Timeout
	//var err error

	verifyChan := make(chan bool, 1)
	if !p.IsRoot() {
		go func() {
			log.Lvl3(p.ServerIdentity(), "starting verification")
			verifyChan <- p.verificationFn(p.Msg, p.Data)
		}()
	}


	if errs := p.SendToChildrenInParallel(&announcement.Announcement); len(errs) > 0 {
		log.Lvl3(p.ServerIdentity().Address, "failed to send announcement to all children")
	}	

	// Collect all responses from children, store them and wait till all have responded or timed out.
	responses := make([]StructResponse, 0)
	if p.IsRoot() {
		select { // one commitment expected from super-protocol
		case response, channelOpen := <-p.ChannelResponse:
			if !channelOpen {
				return nil
			}
			responses = append(responses, response)
		case <-time.After(p.Timeout):
			// the timeout here should be shorter than the main protocol timeout
			// because main protocol waits on the channel below

			p.subleaderNotResponding <- true
			return nil
		}
	} else {
		t := time.After(p.Timeout / 2)
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
	}

	// TODO
	//ok := true
	var ok bool


	if p.IsRoot() {
		// send response to super-protocol
		if len(responses) != 1 {
			return fmt.Errorf(
				"root node in subprotocol should have received 1 signature response, but received %v",
				len(responses))
		}
		p.subResponse <- responses[0]
	} else {

		ok = <-verifyChan
		if !ok {
			log.Lvl2(p.ServerIdentity().Address, "verification failed, unsetting the mask")
		}

		// unset the mask if the verification failed and remove commitment
		
		// Generate own signature and aggregate with all children signatures
		signaturePoint, finalMask, err := generateSignature(p.pairingSuite, p.TreeNodeInstance, p.Publics, responses, p.Msg, ok)

		if err != nil {
			return err
		}
		log.Lvl3(p.TreeNodeInstance.ServerIdentity().Address, "ZZZZZZZZZZZZZZZZZZZZZZZZ", finalMask.mask)

		tmp, err := PointToByteSlice(p.pairingSuite, signaturePoint)

		var found bool
		if !ok {
			for i := range p.Publics {
				if p.Public().Equal(p.Publics[i]) {
					finalMask.SetBit(i, false)
					found = true
					break
				}
			}
		}
		if !ok && !found {
			return fmt.Errorf("%s was unable to find its own public key", p.ServerIdentity().Address)
		}

		if !ok {
			return errors.New("stopping because we won't send to parent")
		}


		err = p.SendToParent(&Response{CoSiReponse:tmp, Mask:finalMask.mask})
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

	annoucement := StructAnnouncement{
		p.TreeNode(),
		Announcement{p.Msg, p.Data, p.Publics, p.Timeout},
	}
	p.ChannelAnnouncement <- annoucement
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