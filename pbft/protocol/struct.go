package protocol


import "github.com/dedis/onet"

// Name can be used from other packages to refer to this protocol.
const DefaultProtocolName = "PBFT"


type PrePrepare struct {
	Msg []byte
	Digest []byte
	Sig []byte
	Sender string
}

type StructPrePrepare struct {
	*onet.TreeNode
	PrePrepare
}


type Prepare struct {
	Digest []byte
	Sig []byte
	Sender string
}

type StructPrepare struct {
	*onet.TreeNode
	Prepare
}


type Commit struct {
	Digest []byte
	Sig []byte
	Sender string
}

type StructCommit struct {
	*onet.TreeNode
	Commit
}


type Reply struct {
	Result []byte
	Sig []byte
	Sender string
}

type StructReply struct {
	*onet.TreeNode
	Reply
}
