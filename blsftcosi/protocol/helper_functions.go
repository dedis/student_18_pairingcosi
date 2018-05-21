package protocol

import (
	"fmt"
	"errors"

	"github.com/dedis/kyber"
	"bls-ftcosi/onet"
	"github.com/dedis/kyber/sign/bls"
	//"github.com/dedis/kyber/sign/cosi"
	"github.com/dedis/kyber/pairing"
	"bls-ftcosi/onet/log"
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
		signatures = append(signatures, r.CoSiReponse)
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
		personalPointSig = ps.G2().Point()
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
	//fmt.Println("xxx sig len", len(signature), signature)
	//fmt.Println("xxx mask len", len(mask.mask), mask.mask)
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
	//fmt.Println("xxx lenCom:", lenCom)
	//fmt.Println("xxx sig len:", len(sig))
	signature := sig[:lenCom]
	//fmt.Println("xxx vbuff",signature)
	sigma := suite.G1().Point()
	if err := sigma.UnmarshalBinary(signature); err != nil {
		return errors.New("unmarshalling of commitment failed")
	}
	fmt.Println("xxx sigma", sigma)


	// Unpack the participation mask and get the aggregate public key
	mask, err := NewMask(suite, publics, nil)
	if err != nil {
		return err
	}
	//fmt.Println("xxx 4")
	mask.SetMask(sig[lenCom:])
	//fmt.Println("xxx 5", mask.mask)
	pks := mask.AggregatePublic
	/*
	ABuff, err := pks.MarshalBinary()
	if err != nil {
		return errors.New("marshalling of aggregate public key failed")
	}
	*/
	//fmt.Println("xxx 6", ABuff)
/*
	// Recompute the challenge
	hash := suite.Hash()
	hash.Write(signature)
	hash.Write(ABuff)
	hash.Write(message)
	buff := hash.Sum(nil)
	*/
	//k := suite.G2().Scalar().SetBytes(buff)

	// k * -aggPublic + s * B = k*-pks + s*B
	// from s = k * a + r => s * B = k * a * B + r * B <=> s*B = k*pks + r*B
	// <=> s*B + k*-pks = r*B
	//minusPublic := suite.G2().Point().Neg(pks)
	//kA := suite.G2().Point().Mul(k, minusPublic)
	//sB := suite.G2().Point().Mul(r, nil)
	//left := suite.G2().Point().Add(kA, nil) // TODO was sB
	//fmt.Println("xxx signature", signature)
	err = bls.Verify(suite, pks, message, signature)
	if err != nil {
		return fmt.Errorf("didn't get a valid signature: %s", err)
	} else {
		fmt.Println("OOOOOOOOOOOOOOOOO  signature verified and is correct!")
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