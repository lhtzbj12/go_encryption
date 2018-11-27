//生成公钥和私钥 pem文件

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"log"
	"os"
)

func main() {
	var bits int
	flag.IntVar(&bits, "b", 1024, "秘钥长度，默认为1024")
	if err := GenRsaKey(bits); err != nil {
		log.Fatal("秘钥文件生成失败")
	}
	log.Println("秘钥文件生成成功")
}

//生成 PKCS1私钥、PKCS8私钥和公钥文件
func GenRsaKey(bits int) error {
	//生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	file, err := os.Create("private_key.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	//生成PKCS8私钥
	pk8Stream := MarshalPKCS8PrivateKey(derStream)
	block = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pk8Stream,
	}
	file, err = os.Create("pkcs8_private_key.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	//生成公钥文件
	publicKey := &privateKey.PublicKey
	defPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: defPkix,
	}
	file, err = os.Create("public_key.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

// 由私钥获取PKCS8公钥 这种方式生成的PKCS8与OpenSSL转成的不一样，但是BouncyCastle里可用
func MarshalPKCS8PrivateKey(key []byte) []byte {
	info := struct {
		Version             int
		PrivateKeyAlgorithm []asn1.ObjectIdentifier
		PrivateKey          []byte
	}{}
	info.Version = 0
	info.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	info.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	info.PrivateKey = key

	k, err := asn1.Marshal(info)
	if err != nil {
		log.Panic(err.Error())
	}
	return k
}

// 由私钥获取PKCS8公钥
func MarshalPKCS8PrivateKey1(key *rsa.PrivateKey) []byte {
	info := struct {
		Version             int
		PrivateKeyAlgorithm []asn1.ObjectIdentifier
		PrivateKey          []byte
	}{}
	info.Version = 0
	info.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	info.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	info.PrivateKey = x509.MarshalPKCS1PrivateKey(key)

	k, err := asn1.Marshal(info)
	if err != nil {
		log.Panic(err.Error())
	}
	return k
}
