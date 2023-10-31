package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

type EcKeyPair struct {
	PrivateKeyPem string
	PublicKeyDer  string
	publicKey     *ecdsa.PublicKey
	privateKey    *ecdsa.PrivateKey
}

func GenerateKey(password string) (*EcKeyPair, error) {
	privateKey, err1 := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err1 != nil {
		return nil, err1
	}
	x509Encoded, err2 := x509.MarshalECPrivateKey(privateKey)
	if err2 != nil {
		return nil, err2
	}
	privateKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	encryptedBytes, err3 := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", privateKeyPem, []byte(password), 5)
	if err3 != nil {
		return nil, err3
	}
	pub, err4 := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err4 != nil {
		return nil, err4
	}
	k := EcKeyPair{
		PrivateKeyPem: string(pem.EncodeToMemory(encryptedBytes)),
		PublicKeyDer:  hex.EncodeToString(pub),
		publicKey:     &privateKey.PublicKey,
		privateKey:    privateKey,
	}
	return &k, nil
}

func (k *EcKeyPair) PrivateSign(buffer []byte, password string) ([]byte, error) {
	if k.privateKey == nil && k.PrivateKeyPem != "" {
		priBinary, decodeRest := pem.Decode([]byte(k.PrivateKeyPem))
		if priBinary == nil {
			return nil, fmt.Errorf("decode private key error: %s", decodeRest)
		}
		d, decryptError := x509.DecryptPEMBlock(priBinary, []byte(password))
		if decryptError != nil {
			return nil, decryptError
		}
		pri, pemDecodeError := pem.Decode(d)
		if pri == nil {
			return nil, fmt.Errorf("decode private key error: %s", pemDecodeError)
		}
		key, parseError := x509.ParseECPrivateKey(pri.Bytes)
		if parseError != nil {
			return nil, parseError
		}
		k.privateKey = key
	}
	digest := sha256.New()
	digest.Write(buffer)
	signature, signError := k.privateKey.Sign(rand.Reader, digest.Sum(nil), nil)
	return signature, signError
}

func (k *EcKeyPair) ModifyPrivateKeyPassword(oldPassword string, password string) (string, error) {
	if k.PrivateKeyPem == "" {
		return "", fmt.Errorf("private key is empty")
	}
	priBinary, _ := pem.Decode([]byte(k.PrivateKeyPem))
	d, err := x509.DecryptPEMBlock(priBinary, []byte(oldPassword))
	if err != nil {
		return "", err
	}
	encryptedBytes, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", d, []byte(password), 5)
	if err != nil {
		return "", err
	}
	k.PrivateKeyPem = string(pem.EncodeToMemory(encryptedBytes))
	k.privateKey = nil
	return k.PrivateKeyPem, nil
}

func (k *EcKeyPair) PublicVerify(data []byte, signature []byte) (bool, error) {
	if k.publicKey == nil && k.PublicKeyDer != "" {
		pubBinary, err1 := hex.DecodeString(k.PublicKeyDer)
		if err1 != nil {
			return false, err1
		}
		pubKey, err2 := x509.ParsePKIXPublicKey(pubBinary)
		if err2 != nil {
			return false, err2
		}
		pk, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("public key error")
		}
		k.publicKey = pk
	}
	if k.publicKey == nil {
		return false, fmt.Errorf("public key error")
	}
	digest := sha256.New()
	digest.Write(data)
	return ecdsa.VerifyASN1(k.publicKey, digest.Sum(nil), signature), nil
}
