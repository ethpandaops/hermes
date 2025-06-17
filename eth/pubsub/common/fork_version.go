package common

import "fmt"

// ForkVersion represents different fork versions
type ForkVersion [4]byte

// Fork version constants
var (
	Phase0ForkVersion    = ForkVersion{0x00, 0x00, 0x00, 0x00}
	AltairForkVersion    = ForkVersion{0x01, 0x00, 0x00, 0x00}
	BellatrixForkVersion = ForkVersion{0x02, 0x00, 0x00, 0x00}
	CapellaForkVersion   = ForkVersion{0x03, 0x00, 0x00, 0x00}
	DenebForkVersion     = ForkVersion{0x04, 0x00, 0x00, 0x00}
	ElectraForkVersion   = ForkVersion{0x05, 0x00, 0x00, 0x00}
)

// String returns the fork version as a hex string
func (f ForkVersion) String() string {
	return fmt.Sprintf("%#x", f[:])
}

// ToBytes returns the fork version as a [4]byte array
func (f ForkVersion) ToBytes() [4]byte {
	return [4]byte(f)
}
