package compression

import (
	"fmt"
)

// SSZSnappyHandler provides SSZ+Snappy compression/decompression for Ethereum messages
type SSZSnappyHandler struct {
	snappy Handler
}

// NewSSZSnappyHandler creates a new SSZ+Snappy compression handler
func NewSSZSnappyHandler() *SSZSnappyHandler {
	return &SSZSnappyHandler{
		snappy: NewSnappyHandler(),
	}
}

// DecompressMessage decompresses a Snappy-compressed SSZ message
func (h *SSZSnappyHandler) DecompressMessage(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty message data")
	}
	
	// Decompress the snappy-encoded data
	decompressed, err := h.snappy.Decompress(data)
	if err != nil {
		return nil, fmt.Errorf("decompress snappy: %w", err)
	}
	
	return decompressed, nil
}

// CompressMessage compresses an SSZ message using Snappy
func (h *SSZSnappyHandler) CompressMessage(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty message data")
	}
	
	// Compress using snappy
	compressed, err := h.snappy.Compress(data)
	if err != nil {
		return nil, fmt.Errorf("compress snappy: %w", err)
	}
	
	return compressed, nil
}

// ValidateCompressedSize checks if the compressed size is within acceptable limits
func (h *SSZSnappyHandler) ValidateCompressedSize(data []byte, maxUncompressedSize int) error {
	// Snappy has built-in protection against zip bombs
	// We can do a quick check on the compressed size
	if len(data) > maxUncompressedSize*10 {
		return fmt.Errorf("compressed data too large: %d bytes", len(data))
	}
	
	// For more accurate validation, we would need to peek at the decompressed size
	// without fully decompressing, but snappy doesn't provide this directly
	
	return nil
}