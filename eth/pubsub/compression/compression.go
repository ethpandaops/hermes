package compression

import (
	"bytes"
	"fmt"
	"io"

	"github.com/golang/snappy"
)

// Handler defines the interface for message compression/decompression
type Handler interface {
	// Compress compresses the input data
	Compress(data []byte) ([]byte, error)
	
	// Decompress decompresses the input data
	Decompress(data []byte) ([]byte, error)
	
	// Name returns the name of the compression method
	Name() string
}

// SnappyHandler implements the Handler interface for Snappy compression
type SnappyHandler struct{}

// NewSnappyHandler creates a new Snappy compression handler
func NewSnappyHandler() Handler {
	return &SnappyHandler{}
}

// Compress compresses data using Snappy
func (s *SnappyHandler) Compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	
	compressed := snappy.Encode(nil, data)
	return compressed, nil
}

// Decompress decompresses Snappy-compressed data
func (s *SnappyHandler) Decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("snappy decode: %w", err)
	}
	
	return decompressed, nil
}

// Name returns the compression method name
func (s *SnappyHandler) Name() string {
	return "snappy"
}

// NoopHandler implements the Handler interface with no compression
type NoopHandler struct{}

// NewNoopHandler creates a new no-op compression handler
func NewNoopHandler() Handler {
	return &NoopHandler{}
}

// Compress returns the data unchanged
func (n *NoopHandler) Compress(data []byte) ([]byte, error) {
	return data, nil
}

// Decompress returns the data unchanged
func (n *NoopHandler) Decompress(data []byte) ([]byte, error) {
	return data, nil
}

// Name returns the compression method name
func (n *NoopHandler) Name() string {
	return "none"
}

// StreamHandler wraps a Handler to work with io.Reader/io.Writer interfaces
type StreamHandler struct {
	handler Handler
}

// NewStreamHandler creates a new stream handler wrapping the given handler
func NewStreamHandler(h Handler) *StreamHandler {
	return &StreamHandler{handler: h}
}

// CompressReader returns a reader that compresses data from the input reader
func (s *StreamHandler) CompressReader(r io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read all: %w", err)
	}
	
	compressed, err := s.handler.Compress(data)
	if err != nil {
		return nil, fmt.Errorf("compress: %w", err)
	}
	
	return bytes.NewReader(compressed), nil
}

// DecompressReader returns a reader that decompresses data from the input reader
func (s *StreamHandler) DecompressReader(r io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read all: %w", err)
	}
	
	decompressed, err := s.handler.Decompress(data)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	
	return bytes.NewReader(decompressed), nil
}