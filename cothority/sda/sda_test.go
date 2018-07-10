package sda

import (
	"testing"

	"bls-ftcosi/cothority/log"
)

// To avoid setting up testing-verbosity in all tests
func TestMain(m *testing.M) {
	log.MainTest(m)
}
