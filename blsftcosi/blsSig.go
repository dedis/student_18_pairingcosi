package main

import (
	"fmt"
	"github.com/dedis/kyber/sign/bls"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/util/random"
)

func testBLS() {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, public := bls.NewKeyPair(suite, random.New())
	sig, err := bls.Sign(suite, private, msg)
	//fmt.Println(sig)
	requireNil(err)
	err = bls.Verify(suite, public, msg, sig)
	requireNil(err)
}

func testBLSAggregate() error {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()

	// (scalar, Point)
	private1, public1 := bls.NewKeyPair(suite, random.New())
	// []byte
	sig1, err := bls.Sign(suite, private1, msg)
	requireNil(err)

	private2, public2 := bls.NewKeyPair(suite, random.New())
	sig2, err := bls.Sign(suite, private2, msg)
	requireNil(err)

	// []byte to Point
	pointSig1 := suite.G1().Point()
	if err := pointSig1.UnmarshalBinary(sig1); err != nil {
		return err
	}

	pointSig2 := suite.G1().Point()
	if err := pointSig2.UnmarshalBinary(sig2); err != nil {
		return err
	}



 	aggSig := pointSig1.Add(pointSig1, pointSig2)
 	aggPublics := public1.Add(public1, public2)

	aggSigSlice, err := aggSig.MarshalBinary()
	if err != nil {
		return err
	}

	err = bls.Verify(suite, aggPublics, msg, aggSigSlice)
	requireNil(err)

	return nil
}

func requireNil(err error) {
	if err != nil {
		fmt.Println("err is not nil!")
	} 
}

func main() {
	testBLS()
	fmt.Println("testBLS OK ")

	testBLSAggregate()
	fmt.Println("testBLSAggregate OK ")

}

