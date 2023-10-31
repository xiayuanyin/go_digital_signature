# go_digital_signature
Digital Signature implement by golang


# Example
```go
const password = "abc123"
initialKeyPair, err := GenerateKey(password)
if err != nil {
    t.Fatal(err)
}
privateKeyStr := initialKeyPair.PrivateKeyPem
publicKeyStr := initialKeyPair.PublicKeyDer
fmt.Println("private key:\n", privateKeyStr)
fmt.Println("public key:\n", publicKeyStr)

key := EcKeyPair{
    PrivateKeyPem: privateKeyStr,
    PublicKeyDer:  publicKeyStr,
}

bodyToSign := []byte("hello world ( to sign )")

signature, err := key.PrivateSign(bodyToSign, password)
if err != nil {
    t.Fatal(err)
}
fmt.Println("sign result(hex):\n", hex.EncodeToString(signature))

res, err := key.PublicVerify(bodyToSign, signature)
if err != nil {
    t.Fatal(err)
}
if res == false {
    t.Fatal("verify failed!")
}

const newPassword = "!!123abc"
_, err = key.ModifyPrivateKeyPassword(password, newPassword)
if err != nil {
    t.Fatal(err)
}
signature2, err := key.PrivateSign(bodyToSign, password)
if err == nil {
    fmt.Println("sign result(hex):\n", hex.EncodeToString(signature2))
    t.Fatal("Error! old password works!")
}

signature3, err := key.PrivateSign(bodyToSign, newPassword)
if err != nil {
    t.Fatal(err)
}
fmt.Println("sign result(hex):\n", hex.EncodeToString(signature3))

```