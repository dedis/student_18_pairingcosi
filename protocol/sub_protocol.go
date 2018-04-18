
package protocol

import (
	"errors"
//	"fmt"
	"sync"
	"time"

//	"github.com/dedis/cothority"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/sign/cosi"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

func init() {
//	GlobalRegisterDefaultProtocols()
}

// SubFtCosi holds the different channels used to receive the different protocol messages.
type SubBlsFtCosi struct {
	*onet.TreeNodeInstance
	Publics        []kyber.Point
	Msg            []byte
	Data           []byte
	
	Timeout        time.Duration
	stoppedOnce    sync.Once
	verificationFn VerificationFn
	suite          cosi.Suite

	// protocol/subprotocol channels
	// these are used to communicate between the subprotocol and the main protocol
	subleaderNotResponding chan bool
	subResponse            chan StructResponse

	// internodes channels
	ChannelChallenge    chan StructChallenge
	ChannelResponse     chan StructResponse
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
	// TODO
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
	p.ChannelChallenge<- challenge
	return nil
}


