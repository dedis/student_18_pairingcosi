package protocol

import (

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/sign/cosi"
	"github.com/dedis/onet"
	"github.com/dedis/kyber/sign/bls"
	"github.com/dedis/kyber/pairing"
	//"github.com/dedis/onet/log"
	//"github.com/dedis/onet/network"
)


func generateSignature(ps pairing.Suite, t *onet.TreeNodeInstance, structResponses []StructResponse,
	msg []byte, ok bool) (kyber.Scalar, error) {

	if t == nil {
		return nil, fmt.Errorf("TreeNodeInstance should not be nil, but is")
	} else if structResponses == nil {
		return nil, fmt.Errorf("StructResponse should not be nil, but is")
	} else if secret == nil {
		return nil, fmt.Errorf("secret should not be nil, but is")
	} else if challenge == nil {
		return nil, fmt.Errorf("challenge should not be nil, but is")
	}

	// extract lists of responses
	var responses []kyber.Scalar
	for _, c := range structResponses {
		responses = append(responses, c.CoSiReponse)
	}

	// generate personal signature
	bls.Sign(ps, t.Private(), msg)


	return 
}