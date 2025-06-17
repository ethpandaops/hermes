package upstream

// sszWrapper wraps already marshaled SSZ data to implement ssz.Marshaler
type sszWrapper struct {
	data []byte
}

func (s *sszWrapper) MarshalSSZ() ([]byte, error) {
	return s.data, nil
}

func (s *sszWrapper) MarshalSSZTo(buf []byte) ([]byte, error) {
	return append(buf, s.data...), nil
}

func (s *sszWrapper) SizeSSZ() int {
	return len(s.data)
}