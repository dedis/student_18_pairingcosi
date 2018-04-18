package protocol

import (
	"crypto/cipher"
	"github.com/dedis/kyber/sign/cosi"
	"fmt"
	"crypto/sha512"
	"hash"
	"time"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
)

// DefaultProtocolName can be used from other packages to refer to this protocol.
// If this name is used, then the suite used to verify signatures must be
// the default cothority.Suite.
const DefaultProtocolName = "blsftCoSiProtoDefault"

// DefaultSubProtocolName the name of the default sub protocol, started by the
// main protocol.
const DefaultSubProtocolName = "blsftSubCoSiProtoDefault"

type blsftCosiSuite struct {
	cosi.Suite
	r cipher.Stream
}

func (m *blsftCosiSuite) Hash() hash.Hash {
	return sha512.New()
}

func (m *blsftCosiSuite) RandomStream() cipher.Stream {
	return m.r
}

// Challenge is the ftcosi challenge message
type Challenge struct {
	Msg []byte // statement to be signed
	Data []byte
	Publics []kyber.Point
	//CoSiChallenge kyber.Scalar
	Timeout time.Duration
}

// StructChallenge just contains Challenge and the data necessary to identify and
// process the message in the onet framework.
type StructChallenge struct {
	*onet.TreeNode
	Challenge
}


// Response is the ftcosi response message
type Response struct {
	CoSiReponse kyber.Scalar
}

// StructResponse just contains Response and the data necessary to identify and
// process the message in the onet framework.
type StructResponse struct {
	*onet.TreeNode
	Response
}


// Stop is a message used to instruct a node to stop its protocol
type Stop struct{}

// StructStop is a wrapper around Stop for it to work with onet
type StructStop struct {
	*onet.TreeNode
	Stop
}



func Test() {
	fmt.Println("yo")
}
