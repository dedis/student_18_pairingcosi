package protocol

import (
	//"bls-ftcosi/bftcosi/cosi"
	//"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	//"gopkg.in/dedis/onet.v1/log"
	"fmt"
	"gopkg.in/dedis/onet.v1/network"
)






func GetSubleaderIDs(tree *onet.Tree, nNodes, nSubtrees int) ([]network.ServerIdentityID, error) {
	exampleTrees, err := GenTrees(tree.Roster, nNodes, nSubtrees)
	if err != nil {
		return nil, fmt.Errorf("error in creation of example tree:%s", err)
	}
	subleadersIDs := make([]network.ServerIdentityID, 0)
	for _, subtree := range exampleTrees {
		if len(subtree.Root.Children) < 1 {
			return nil, fmt.Errorf("expected a subtree with at least a subleader, but found none")
		}
		subleadersIDs = append(subleadersIDs, subtree.Root.Children[0].ServerIdentity.ID)
	}
	return subleadersIDs, nil
}


func GetLeafsIDs(tree *onet.Tree, nNodes, nSubtrees int) ([]network.ServerIdentityID, error) {
	exampleTrees, err := GenTrees(tree.Roster, nNodes, nSubtrees)
	if err != nil {
		return nil, fmt.Errorf("error in creation of example tree:%s", err)
	}
	leafsIDs := make([]network.ServerIdentityID, 0)
	for _, subtree := range exampleTrees {
		if len(subtree.Root.Children) < 1 {
			return nil, fmt.Errorf("expected a subtree with at least a subleader, but found none")
		}
		for _, leaf := range subtree.Root.Children[0].Children {
			leafsIDs = append(leafsIDs, leaf.ServerIdentity.ID)
		}
	}
	return leafsIDs, nil
}