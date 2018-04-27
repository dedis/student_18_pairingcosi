package protocol

import (
	"fmt"

	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/kyber/sign/bls"
	"github.com/dedis/kyber/pairing"
	"github.com/dedis/onet/log"
	//"github.com/dedis/onet/network"
)


// Sign the message with this node and aggregates with all child signatures (in structResponses)
func generateSignature(ps pairing.Suite, t *onet.TreeNodeInstance, structResponses []StructResponse,
	msg []byte, ok bool) (kyber.Point, error) {

	if t == nil {
		return nil, fmt.Errorf("TreeNodeInstance should not be nil, but is")
	} else if structResponses == nil {
		return nil, fmt.Errorf("StructResponse should not be nil, but is")
	} else if msg == nil {
		return nil, fmt.Errorf("msg should not be nil, but is")
	}

	// extract lists of responses
	var signatures []kyber.Point
	for _, c := range structResponses {
		signatures = append(signatures, c.CoSiReponse)
	}

	// generate personal signature and append to other sigs
	personalSig, err := bls.Sign(ps, t.Private(), msg)
	if err != nil {
			return nil, err
	}
	personalPointSig, err := signedByteSliceToPoint(ps, personalSig)
	if !ok {
		personalPointSig = ps.G1().Point()
	}

	signatures = append(signatures, personalPointSig)

	// Aggregate all signatures
	aggSignature, err := aggregateSignatures(ps, signatures)
	if err != nil {
		log.Lvl3(t.ServerIdentity().Address, "failed to create aggregate signature")
		return nil, err
	}
	
	log.Lvl3(t.ServerIdentity().Address, "is done aggregating signatures with total of", len(signatures), "signatures")

	return aggSignature, nil
}

func signedByteSliceToPoint(ps pairing.Suite, sig []byte) (kyber.Point, error) {
	pointSig := ps.G1().Point()
	if err := pointSig.UnmarshalBinary(sig); err != nil {
		return nil, err
	}

	return pointSig, nil
}

// AggregateResponses returns the sum of given responses.
// TODO add mask data?
func aggregateSignatures(suite pairing.Suite, signatures []kyber.Point) (kyber.Point, error) {
	if signatures == nil {
		return nil, fmt.Errorf("no signatures provided")
	}
	r := suite.G1().Point()
	for _, signature := range signatures {
		r = r.Add(r, signature)
	}
	return r, nil
}