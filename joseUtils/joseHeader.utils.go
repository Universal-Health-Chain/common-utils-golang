package joseUtils

// KeyID gets Key ID from JOSE headers.
func (h Headers) KeyID() (string, bool) {
	return h.stringValue(HeaderKeyID)
}

// SenderKeyID gets the sender Key ID from Jose headers.
func (h Headers) SenderKeyID() (string, bool) {
	return h.stringValue(HeaderSenderKeyID)
}

// Algorithm gets Algorithm from JOSE headers.
func (h Headers) Algorithm() (string, bool) {
	return h.stringValue(HeaderAlgorithm)
}

// Encryption gets content encryption algorithm from JOSE headers.
func (h Headers) Encryption() (string, bool) {
	return h.stringValue(HeaderEncryption)
}

// Type gets content encryption type from JOSE headers.
func (h Headers) Type() (string, bool) {
	return h.stringValue(HeaderType)
}

// ContentType gets the payload content type from JOSE headers.
func (h Headers) ContentType() (string, bool) {
	return h.stringValue(HeaderContentType)
}

func (h Headers) stringValue(key string) (string, bool) {
	raw, ok := h[key]
	if !ok {
		return "", false
	}

	str, ok := raw.(string)

	return str, ok
}
