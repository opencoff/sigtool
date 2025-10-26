// helper routines to maintain backwards compat with gogo

package pb

func (m *Header) Size() int {
	return m.SizeVT()
}

func (m *Header) MarshalTo(buf []byte) (int, error) {
	return m.MarshalToVT(buf)
}

func (m *Header) Unmarshal(buf []byte) error {
	return m.UnmarshalVT(buf)
}
