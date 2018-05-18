package protocol

import (
	"fmt"
	"errors"

	"github.com/dedis/kyber"
	"bls-ftcosi/onet"
	"github.com/dedis/kyber/sign/bls"
	"github.com/dedis/kyber/sign/cosi"
	"github.com/dedis/kyber/pairing"
	"bls-ftcosi/onet/log"
)


// AggregateCommitments returns the sum of the given commitments and the
// bitwise OR of the corresponding masks.
func AggregateCommitments(ps pairing.Suite, commitments []kyber.Point, masks [][]byte) (sum kyber.Point, commits []byte, err error) {
	if len(commitments) != len(masks) {
		return nil, nil, errors.New("mismatching lengths of commitment and mask slices")
	}
	aggCom := ps.Point().Null()
	aggMask := make([]byte, len(masks[0]))

	for i := range commitments {
		aggCom = ps.Point().Add(aggCom, commitments[i])
		aggMask, err = AggregateMasks(aggMask, masks[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return aggCom, aggMask, nil
}

type Mask struct {
	mask            []byte
	publics         []kyber.Point
	AggregatePublic kyber.Point
}

// NewMask returns a new participation bitmask for cosigning where all
// cosigners are disabled by default. If a public key is given it verifies that
// it is present in the list of keys and sets the corresponding index in the
// bitmask to 1 (enabled).
func newMask(ps pairing.Suite, publics []kyber.Point, myKey kyber.Point) (*Mask, error) {
	m := &Mask{
		publics: publics,
	}
	m.mask = make([]byte, m.Len())
	m.AggregatePublic = ps.Point().Null()
	if myKey != nil {
		found := false
		for i, key := range publics {
			if key.Equal(myKey) {
				m.SetBit(i, true)
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("key not found")
		}
	}
	return m, nil
}


// Sign the message with this node and aggregates with all child signatures (in structResponses)
func generateSignature(ps pairing.Suite, t *onet.TreeNodeInstance, publics []kyber.Point, structResponses []StructResponse,
	msg []byte, ok bool) (kyber.Point, error) {

	if t == nil {
		return nil, fmt.Errorf("TreeNodeInstance should not be nil, but is")
	} else if structResponses == nil {
		return nil, fmt.Errorf("StructResponse should not be nil, but is")
	} else if publics == nil {
		return nil, nil, nil, fmt.Errorf("publics should not be nil, but is")
	} else if msg == nil {
		return nil, fmt.Errorf("msg should not be nil, but is")
	}

	// extract lists of responses
	var signatures []kyber.Point
	var masks [][]byte
	for _, r := range structResponses {
		signatures = append(signatures, r.CoSiReponse)
		masks = append(masks, r.Mask)
	}

	//generate personal mask
	personalMask, err := newMask(ps, publics, t.Public())
	masks = append(masks, personalMask.Mask())
	// TODO

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
	aggSignature, err := aggregateSignatures(ps, signatures, masks)
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
func aggregateSignatures(suite pairing.Suite, signatures []kyber.Point, masks [][]byte) (kyber.Point, error) {
	if signatures == nil {
		return nil, fmt.Errorf("no signatures provided")
	}
	r := suite.G1().Point()
	for _, signature := range signatures {
		r = r.Add(r, signature)
	}
	return r, nil
}