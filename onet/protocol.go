package onet

import (
	"github.com/cypherium/cypherBFT/onet/network"
	uuid "gopkg.in/satori/go.uuid.v1"
)

// ProtocolID uniquely identifies a protocol
type ProtocolID uuid.UUID

// String returns canonical string representation of the ID
func (pid ProtocolID) String() string {
	return uuid.UUID(pid).String()
}

// Equal returns true if and only if pid2 equals this ProtocolID.
func (pid ProtocolID) Equal(pid2 ProtocolID) bool {
	return uuid.Equal(uuid.UUID(pid), uuid.UUID(pid2))
}

// IsNil returns true iff the ProtocolID is Nil
func (pid ProtocolID) IsNil() bool {
	return pid.Equal(ProtocolID(uuid.Nil))
}

// ProtocolNameToID returns the ProtocolID corresponding to the given name.
func ProtocolNameToID(name string) ProtocolID {
	url := network.NamespaceURL + "protocolname/" + name
	return ProtocolID(uuid.NewV3(uuid.NamespaceURL, url))
}
