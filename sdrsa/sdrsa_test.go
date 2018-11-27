package sdrsa_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/lhtzbj12/go_encryption/sdrsa"
)

var privateKey, publicKey []byte

func init() {
	var err error
	publicKey, err = ioutil.ReadFile("public_key.pem")
	if err != nil {
		os.Exit(-1)
	}
	privateKey, err = ioutil.ReadFile("private_key.pem")
	if err != nil {
		os.Exit(-1)
	}
	//fmt.Printf("%s\n", publicKey)
	//fmt.Printf("%s\n", privateKey)
}
func TestEncrypt(t *testing.T) {
	var tests = []string{
		"abasdf中222国",
		"12345678",
		"sjgfjvbj",
	}
	for _, test := range tests {
		enc, _ := sdrsa.Encrypt([]byte(test), publicKey)
		got, _ := sdrsa.Decrypt(enc, privateKey, sdrsa.PKCS1)
		if string(got) != test {
			t.Errorf("Failed (%q) = %v", test, string(got))
		}
	}
}

func TestSign(t *testing.T) {
	var tests = []string{
		"abasdf中222国",
		"12345678",
		"sjgfjvbj",
	}
	for _, test := range tests {
		sign, _ := sdrsa.Sign([]byte(test), privateKey, sdrsa.PKCS1)
		err := sdrsa.SignVer([]byte(test), sign, publicKey)
		if err != nil {
			t.Errorf("Failed %s", test)
		}
	}
}
