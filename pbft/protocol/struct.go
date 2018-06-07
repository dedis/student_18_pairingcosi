package protocol


import "gopkg.in/dedis/onet.v2"

// Name can be used from other packages to refer to this protocol.
const DefaultProtocolName = "PBFT"




type PrePrepare struct {
	Msg []byte
	Digest []byte // TODO can remove but ok
}

type StructPrePrepare struct {
	*onet.TreeNode
	PrePrepare
}

type Prepare struct {
	Digest []byte
}

type StructPrepare struct {
	*onet.TreeNode
	Prepare
}

type Commit struct {
	Digest []byte
}

type StructCommit struct {
	*onet.TreeNode
	Commit
}

// Reply returns the count of all children.
type Reply struct {
	Result []byte
}

// StructReply just contains Reply and the data necessary to identify and
// process the message in the sda framework.
type StructReply struct {
	*onet.TreeNode
	Reply
}

