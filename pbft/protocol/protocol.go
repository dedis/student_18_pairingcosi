package protocol

/*
The `NewProtocol` method is used to define the protocol and to register
the handlers that will be called if a certain type of message is received.
The handlers will be treated according to their signature.

The protocol-file defines the actions that the protocol needs to do in each
step. The root-node will call the `Start`-method of the protocol. Each
node will only use the `Handle`-methods, and not call `Start` again.
*/

import (
	"errors"
	"sync"
	"time"
	"bytes"
	"math"

	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"

	"crypto/sha512"
)

func init() {
	log.SetDebugVisible(3)
	network.RegisterMessage(PrePrepare{})
	network.RegisterMessage(Prepare{})
	network.RegisterMessage(Commit{})
	network.RegisterMessage(Reply{})
	onet.GlobalProtocolRegister(DefaultProtocolName, NewProtocol)
}


type VerificationFn func(msg []byte, data []byte) bool

var defaultTimeout = 5 * time.Second

type PbftProtocol struct {
	*onet.TreeNodeInstance

	Msg					[]byte
	nNodes				int

	FinalReply 			chan []byte
	startChan       	chan bool
	stoppedOnce    		sync.Once
	verificationFn  	VerificationFn
	Timeout 			time.Duration

	ChannelPrePrepare   chan StructPrePrepare
	ChannelPrepare 		chan StructPrepare
	ChannelCommit		chan StructCommit
	ChannelReply		chan StructReply


}

// Check that *PbftProtocol implements onet.ProtocolInstance
var _ onet.ProtocolInstance = (*PbftProtocol)(nil)

// NewProtocol initialises the structure for use in one round
func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	t := &PbftProtocol{
		TreeNodeInstance: 	n,
		nNodes: 			n.Tree().Size(),
		startChan:       	make(chan bool, 1),
		FinalReply:   	make(chan []byte, 1),
	}

	for _, channel := range []interface{}{
		&t.ChannelPrePrepare,
		&t.ChannelPrepare,
		&t.ChannelCommit,
		&t.ChannelReply,
	} {
		err := t.RegisterChannel(channel)
		if err != nil {
			return nil, errors.New("couldn't register channel: " + err.Error())
		}
	}
	/*
	err := c.RegisterHandler(c.HandleStop)
	if err != nil {
		return nil, errors.New("couldn't register stop handler: " + err.Error())
	}
	*/
	return t, nil
}

// Start sends the Announce-message to all children
func (pbft *PbftProtocol) Start() error {
	// TODO verify args not null

	log.Lvl3("Starting PbftProtocol")
	
	//pbft.startChan <- true

	return nil
}

func (pbft *PbftProtocol) Dispatch() error {

	log.Lvl3(pbft.ServerIdentity(), "------------------- Started node")

	if pbft.IsRoot() {
		// send pre-prepare phase
		digest := sha512.Sum512(pbft.Msg) // TODO digest is correct?
		go func() {
			if errs := pbft.SendToChildrenInParallel(&PrePrepare{Msg:pbft.Msg, Digest:digest[:]}); len(errs) > 0 {
				log.Lvl3(pbft.ServerIdentity(), "failed to send pre-prepare to all children")
			}
		}()
	} else {
		// wait for pre-prepare message from leader
		log.Lvl3("Waiting for preprepare")
		preprepare, channelOpen := <-pbft.ChannelPrePrepare
		if !channelOpen {
			return nil
		}
		log.Lvl3(pbft.ServerIdentity(), "Received PrePrepare. Verifying...")

		// verify
		digest := sha512.Sum512(preprepare.Msg)

		if !bytes.Equal(digest[:], preprepare.Digest) {
			log.Lvl3(pbft.ServerIdentity(), "received pre-prepare digest is not correct")
		}
		
		// broadcast Prepare message to all nodes
		if errs := pbft.Broadcast(&Prepare{Digest:digest[:]}); len(errs) > 0 {
			log.Lvl3(pbft.ServerIdentity(), "error while broadcasting prepare message")

		}
		log.Lvl3(pbft.ServerIdentity(), "BROADCAST PREPARE")
	}


	// wait for at least 2/3rds prepare broadcat messages
	t := time.After(defaultTimeout * 2)
	responseThreshold := int(math.Ceil(float64(pbft.nNodes - 2) * (float64(2)/float64(3))))

	nReceivedPrepareMessages := 0

	nMaxWaitMessages := pbft.nNodes - 2 // total tree nodes minus leader and itself
	if pbft.IsRoot() {
		nMaxWaitMessages = pbft.nNodes - 1 // Except for the leader
	}
	
loop:
	for  i := 0; i <= nMaxWaitMessages - 1; i++  {
		select {
		case prepare, channelOpen := <-pbft.ChannelPrepare:
			if !channelOpen {
				return nil
			}
			_ = prepare
			nReceivedPrepareMessages++
		case <-t:
			// TODO
			log.Lvl3(pbft.ServerIdentity(), "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
			break loop
		}
		
	}

	if !(nReceivedPrepareMessages >= responseThreshold) {
		log.Lvl3(pbft.ServerIdentity(), "node didn't receive enough prepare messages. Stopping.")
		return nil
	} else {
		log.Lvl3(pbft.ServerIdentity(), "================================ Received enough prepare messages (> 2/3)")
	}



	digest := sha512.Sum512(pbft.Msg)

	// Broadcast commit message
	if errs := pbft.Broadcast(&Commit{Digest:digest[:]}); len(errs) > 0 {
		log.Lvl3(pbft.ServerIdentity(), "error while broadcasting commit message")
	}

	nReceivedCommitMessages := 0

commitLoop:
	for  i := 0; i <= nMaxWaitMessages - 1; i++  {
		select {
		case commit, channelOpen := <-pbft.ChannelCommit:
			if !channelOpen {
				return nil
			}
			_ = commit
			nReceivedCommitMessages++
		case <-t:
			// TODO
			log.Lvl3(pbft.ServerIdentity(), "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy")
			break commitLoop
		}
	}

	if !(nReceivedCommitMessages >= responseThreshold) {
		log.Lvl3(pbft.ServerIdentity(), "node didn't receive enough commit messages. Stopping.")
		return nil
	} else {
		log.Lvl3(pbft.ServerIdentity(), "#################################### Received enough commit messages (> 2/3)")
	}


	replyThreshold := int(math.Ceil(float64(pbft.nNodes) * (float64(2)/float64(3)))) -1// TODO +1 ??
	receivedReplies := 0

	if pbft.IsRoot() {
replyLoop:
		for  i := 0; i <= replyThreshold - 1; i++  {
			//var digest []byte
			select {
			case reply, channelOpen := <-pbft.ChannelReply:
				if !channelOpen {
					return nil
				}
				receivedReplies++
				log.Lvl3("Leader got one reply, total is", receivedReplies)

				_ = reply
				
			case <-time.After(defaultTimeout * 2):
				// wait a bit longer than the protocol timeout
				log.Lvl3("didn't get reply in time")
				break replyLoop
			}
		}

		pbft.FinalReply <- digest[:]

	} else {
		err := pbft.SendToParent(&Reply{Result:digest[:]})
		if err != nil {
			return err
		}
	}

	return nil
}


// Shutdown stops the protocol
func (pbft *PbftProtocol) Shutdown() error {
	pbft.stoppedOnce.Do(func() {
		close(pbft.ChannelPrePrepare)
		close(pbft.ChannelPrepare)
		close(pbft.ChannelCommit)
		close(pbft.ChannelReply)
	})
	return nil
}



// TODO
// How to hash to create Digest?
// What variables are important?
// e.g. Timeout in children? How to set?
// Do we have to wait for all nodes to ok prepare step? Or can go directly to commit step when prepare is ok?
// In paper, d =? D(m)