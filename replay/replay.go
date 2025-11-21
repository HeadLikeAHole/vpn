// Package replay implements an efficient anti-replay algorithm as specified in RFC 6479.
package replay

const (
	// used for division by 64
	blockBitShift = 6
	// number of bits in a block, must be power of 2
	nBits = 1 << blockBitShift // 1 << 6 == 64
	// number of blocks in the ring buffer, must be power of 2
	nBlocks    = 1 << 7                // 1 << 7 == 128
	bitMask    = nBits - 1             // 64 - 1 == 63 == 0b0011_1111
	blockMask  = nBlocks - 1           // 128 - 1 == 127 == 0b0111_1111
	windowSize = (nBlocks - 1) * nBits // (128 - 1) * 64 = 8128
)

type block uint64

// A Filter rejects replayed messages by checking if message counter value is
// within a sliding window of previously received messages.
// The zero value for Filter is an empty filter ready to use.
// Filters are unsafe for concurrent use.
type Filter struct {
	// highest value seen so far
	last uint64
	// Bit field ring buffer.
	// Each bit represents a counter value.
	ring [nBlocks]block // 128 x 64 = 8192
}

// Validate checks if the counter value should be accepted.
// Out of limit values (>= limit) are always rejected.
func (f *Filter) Validate(value, limit uint64) bool {
	// limit defines the maximum acceptable counter value.
	// Prevents value overflow attacks.
	if value >= limit {
		return false
	}
	// divide by 64 to get block index, because
	// each block contains 64 bits
	// 1: 10 >> 6
	// 1: 0 = 0b1010 >> 6
	// 2: 10000 >> 6
	// 2: 156 = 0b1001_1100 = 0b0010_0111_0001_0000 >> 6
	blockIndex := value >> blockBitShift
	// 1: 10 > 0
	// 2: 10000 > 10
	if value > f.last { // move window forward
		// 1: 0 = 0 >> 6
		// 2: 0 = 10 >> 6
		// 2: 0 = 0b1010 >> 6
		currentIndex := f.last >> blockBitShift
		// 1: 0 = 0 - 0
		// 2: 156 = 156 - 0
		diff := blockIndex - currentIndex
		// 1: 0 > 128
		// 2: 156 > 128
		if diff > nBlocks {
			diff = nBlocks // cap diff to clear the ring
		}
		// 2: i = 0 + 1; i <= 0 + 128
		for i := currentIndex + 1; i <= currentIndex+diff; i++ {
			f.ring[i&blockMask] = 0
		}
		f.last = value
	} else if f.last-value > windowSize { // behind current window
		return false
	}
	// check and set bit
	// 1: 0 = 0 & 0b0111_1111
	blockIndex &= blockMask
	// Modulo division to get bit index.
	// 1: 10 = 0b0000_1010 & 0b0011_1111
	bitIndex := value & bitMask
	// 1: 0
	old := f.ring[blockIndex]
	// 1: 0 | 1<<10
	// 1: 0 | 0b100_0000_0000
	new := old | 1<<bitIndex
	f.ring[blockIndex] = new
	// 1: 0 != 0b100_0000_0000
	return old != new
}

// Reset resets the filter to empty state.
func (f *Filter) Reset() {
	f.last = 0
	f.ring[0] = 0
}
