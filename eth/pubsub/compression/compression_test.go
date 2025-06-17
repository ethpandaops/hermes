package compression

import (
	"bytes"
	"testing"
)

func TestSnappyHandler(t *testing.T) {
	handler := NewSnappyHandler()
	
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "small data",
			data: []byte("hello world"),
		},
		{
			name: "large data",
			data: bytes.Repeat([]byte("test data "), 1000),
		},
		{
			name: "binary data",
			data: []byte{0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test compression
			compressed, err := handler.Compress(tc.data)
			if err != nil {
				t.Fatalf("Compress failed: %v", err)
			}
			
			// Test decompression
			decompressed, err := handler.Decompress(compressed)
			if err != nil {
				t.Fatalf("Decompress failed: %v", err)
			}
			
			// Verify data integrity
			if !bytes.Equal(tc.data, decompressed) {
				t.Errorf("Data mismatch: original len=%d, decompressed len=%d",
					len(tc.data), len(decompressed))
			}
		})
	}
}

func TestNoopHandler(t *testing.T) {
	handler := NewNoopHandler()
	
	testData := []byte("test data")
	
	// Test compression (should be unchanged)
	compressed, err := handler.Compress(testData)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}
	
	if !bytes.Equal(testData, compressed) {
		t.Error("NoopHandler changed data during compression")
	}
	
	// Test decompression (should be unchanged)
	decompressed, err := handler.Decompress(testData)
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}
	
	if !bytes.Equal(testData, decompressed) {
		t.Error("NoopHandler changed data during decompression")
	}
}

func TestSSZSnappyHandler(t *testing.T) {
	handler := NewSSZSnappyHandler()
	
	// Simulate SSZ-encoded data
	testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	
	// Test compression
	compressed, err := handler.CompressMessage(testData)
	if err != nil {
		t.Fatalf("CompressMessage failed: %v", err)
	}
	
	// Test decompression
	decompressed, err := handler.DecompressMessage(compressed)
	if err != nil {
		t.Fatalf("DecompressMessage failed: %v", err)
	}
	
	// Verify data integrity
	if !bytes.Equal(testData, decompressed) {
		t.Errorf("Data mismatch after round trip")
	}
}

func TestValidateCompressedSize(t *testing.T) {
	handler := NewSSZSnappyHandler()
	
	testCases := []struct {
		name                string
		dataSize            int
		maxUncompressedSize int
		expectError         bool
	}{
		{
			name:                "within limits",
			dataSize:            100,
			maxUncompressedSize: 1000,
			expectError:         false,
		},
		{
			name:                "exceeds limits",
			dataSize:            10000,
			maxUncompressedSize: 100,
			expectError:         true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := bytes.Repeat([]byte{0x42}, tc.dataSize)
			err := handler.ValidateCompressedSize(data, tc.maxUncompressedSize)
			
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}