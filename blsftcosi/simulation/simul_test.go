package main_test

import (
	"testing"

	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/simul"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestSimulation(t *testing.T) {
	simul.Start("protocol.toml")
}
