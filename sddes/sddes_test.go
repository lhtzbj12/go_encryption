package sddes_test

import (
	"testing"

	"github.com/lhtzbj12/go_encryption/sddes"
)

func TestDES(t *testing.T) {
	var tests = []struct {
		input string
		key   string
		iv    string
	}{
		{"", "12345678", "sjgfjvbj"},
		{"ab中国", "12345678", "sjgfjvbj"},
		{"abasdf中222国", "12345678", "sjgfjvbj"},
	}
	for _, test := range tests {
		enc, _ := sddes.Encrypt([]byte(test.input), []byte(test.key), []byte(test.iv))
		got, _ := sddes.Decrypt(enc, []byte(test.key), []byte(test.iv))
		if string(got) != test.input {
			t.Errorf("IsPalindrome(%q) = %v", test.input, got)
		}
	}
}

func BenchmarkDES(b *testing.B) {
	var tests = []struct {
		input string
		key   string
		iv    string
	}{
		{"", "12345678", "sjgfjvbj"},
		{"ab中国", "12345678", "sjgfjvbj"},
		{"abasdf中222国", "12345678", "sjgfjvbj"},
	}
	for i := 0; i < b.N; i++ {
		for _, test := range tests {
			enc, _ := sddes.Encrypt([]byte(test.input), []byte(test.key), []byte(test.iv))
			sddes.Decrypt(enc, []byte(test.key), []byte(test.iv))
		}
	}

}

func TestTriple(t *testing.T) {
	var tests = []struct {
		input string
		key   string
		iv    string
	}{
		{"", "123456781234567812345678", "sjgfjvbj"},
		{"a!b中国", "123456781234567812345678", "sjgfjvbj"},
		{"abasd!!!f中222国", "123456781234567812345678", "sjgfjvbj"},
	}
	for _, test := range tests {
		enc, _ := sddes.TripleEncrypt([]byte(test.input), []byte(test.key), []byte(test.iv))
		got, _ := sddes.TripleDecrypt(enc, []byte(test.key), []byte(test.iv))
		if string(got) != test.input {
			t.Errorf("IsPalindrome(%q) = %v", test.input, got)
		}
	}
}
