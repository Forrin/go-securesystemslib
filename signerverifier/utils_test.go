package signerverifier

import (
	"crypto"
	"encoding/hex"
	"testing"
)

func TestGetDigest(t *testing.T) {
	cases := []struct {
		data            []byte
		hash_function   crypto.Hash
		expected_output string
	}{
		{[]byte("test"), crypto.SHA256, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
		{[]byte("test"), crypto.SHA512, "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"},
		{[]byte("test"), crypto.SHA384, "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9"},
	}

	for _, value := range cases {
		digest, _ := getDigest(value.data, value.hash_function)
		if hex.EncodeToString(digest) != value.expected_output {
			t.Errorf("got %v, expected %v", digest, value.expected_output)
		}
	}
}

func TestErrorGetDigest(t *testing.T) {
	cases := []struct {
		hash_function   crypto.Hash
		expected_output string
	}{
		{crypto.SHA1, "unsupported hash function"},
	}

	for _, value := range cases {
		_, err := getDigest([]byte("this data doesn't matter"), value.hash_function)
		if err.Error() != value.expected_output {
			t.Errorf("got %v, expected %v", err.Error(), value.expected_output)
		}
	}
}
