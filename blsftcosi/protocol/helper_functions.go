package protocol

import (
	"fmt"

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
	} else if msg == nil {
		return nil, fmt.Errorf("msg should not be nil, but is")
	}

	// extract lists of responses
	var responses []kyber.Scalar
	for _, c := range structResponses {
		responses = append(responses, c.CoSiReponse)
	}

	// generate personal signature; returns a []byte
	personalSignature, err := bls.Sign(ps, t.Private(), msg)
	if err != nil {
			return nil, err
	}
	// TODO set to null value if not ok
	//if !ok {
	//	personalSignature = s.Scalar().Zero()
	//}

	return 
}

// AggregateResponses returns the sum of given responses.
// TODO add mask data?
func AggregateSignatures(suite Suite, signatures []kyber.Point) (kyber.Point, error) {
	if signatures == nil {
		return nil, errors.New("no signatures provided")
	}
	r := suite.G1().Point()
	for _, signature := range signatures {
		r = r.Add(r, signature)
	}
	return r, nil
}