package protocol

import (
	"fmt"
	"errors"

	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/kyber.v2/sign/bls"
	"gopkg.in/dedis/kyber.v2/pairing"
	"gopkg.in/dedis/onet.v2/log"
)



// Sign the message with this node and aggregates with all child signatures (in structResponses)
// Also aggregates the child bitmasks
func generateSignature(ps pairing.Suite, t *onet.TreeNodeInstance, publics []kyber.Point, structResponses []StructResponse,
	msg []byte, ok bool) (kyber.Point, *Mask, error) {

	if t == nil {
		return nil, nil, fmt.Errorf("TreeNodeInstance should not be nil, but is")
	} else if structResponses == nil {
		return nil, nil, fmt.Errorf("StructResponse should not be nil, but is")
	} else if publics == nil {
		return nil, nil, fmt.Errorf("publics should not be nil, but is")
	} else if msg == nil {
		return nil, nil, fmt.Errorf("msg should not be nil, but is")
	}

	// extract lists of responses
	var signatures []kyber.Point
	var masks [][]byte

	for _, r := range structResponses {
		atmp, err := signedByteSliceToPoint(ps, r.CoSiReponse)
		_ = err
		signatures = append(signatures, atmp)
		masks = append(masks, r.Mask)
	}

	//generate personal mask
	personalMask, err := NewMask(ps, publics, t.Public())
	masks = append(masks, personalMask.Mask())
	// TODO

	// TODO if not ok, remove bit in mask

	// generate personal signature and append to other sigs
	personalSig, err := bls.Sign(ps, t.Private(), msg)

	if err != nil {
			return nil,nil,  err
	}
	personalPointSig, err := signedByteSliceToPoint(ps, personalSig)
	if !ok {
		personalPointSig = ps.G1().Point()
	}

	signatures = append(signatures, personalPointSig)

	// Aggregate all signatures
	aggSignature, aggMask, err := aggregateSignatures(ps, signatures, masks)
	if err != nil {
		log.Lvl3(t.ServerIdentity().Address, "failed to create aggregate signature")
		return nil, nil, err
	}

	//create final aggregated mask
	finalMask, err := NewMask(ps, publics, nil)
	if err != nil {
		return nil, nil, err
	}
	err = finalMask.SetMask(aggMask)
	if err != nil {
		return nil, nil, err
	}
	
	log.Lvl3(t.ServerIdentity().Address, "is done aggregating signatures with total of", len(signatures), "signatures")

	return aggSignature, finalMask, nil
}

func signedByteSliceToPoint(ps pairing.Suite, sig []byte) (kyber.Point, error) {
	pointSig := ps.G1().Point()

	if err := pointSig.UnmarshalBinary(sig); err != nil {
		return nil, err
	}

	return pointSig, nil
}

func PointToByteSlice(ps pairing.Suite, sig kyber.Point) ([]byte, error) {
	byteSig, err := sig.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return byteSig, nil
}

// AggregateResponses returns the sum of given responses.
// TODO add mask data?
func aggregateSignatures(suite pairing.Suite, signatures []kyber.Point, masks [][]byte) (sum kyber.Point, sig []byte, err error) {
	if signatures == nil {
		return nil, nil, fmt.Errorf("no signatures provided")
	}
	aggMask := make([]byte, len(masks[0]))
	r := suite.G1().Point()

	for i, signature := range signatures {

		r = r.Add(r, signature)
		aggMask, err = AggregateMasks(aggMask, masks[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return r, aggMask, nil
}

func AppendSigAndMask(signature []byte, mask *Mask) ([]byte) {
	return append(signature, mask.mask...)
}

// Verify checks the given cosignature on the provided message using the list
// of public keys and cosigning policy.
func Verify(suite pairing.Suite, publics []kyber.Point, message, sig []byte) error {
	if publics == nil {
		return errors.New("no public keys provided")
	}
	if message == nil {
		return errors.New("no message provided")
	}
	if sig == nil {
		return errors.New("no signature provided")
	}


	lenCom := suite.G1().PointLen()
	signature := sig[:lenCom]



	// Unpack the participation mask and get the aggregate public key
	mask, err := NewMask(suite, publics, nil)
	if err != nil {
		return err
	}
	//fmt.Println("xxx 4")
	mask.SetMask(sig[lenCom:])
	//fmt.Println("xxx 5", mask.mask)
	pks := mask.AggregatePublic

	
	err = bls.Verify(suite, pks, message, signature)
	if err != nil {
		return fmt.Errorf("didn't get a valid signature: %s", err)
	} else {
		fmt.Println("Signature verified and is correct!")
	}

	// TODO check mask
/*
	if !left.Equal(sigma) || !check(mask) {
		return errors.New("invalid signature")
	}
	*/

	return nil
}

// Check verifies that all participants have contributed to a collective
// signature.
func check(m *Mask) bool {
	return m.CountEnabled() == m.CountTotal()
}