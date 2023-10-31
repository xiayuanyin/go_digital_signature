# go_digital_signature
Digital Signature implement by golang


# Example
```go
const password = "abc123"
// generate key pair with private key password
initialKeyPair, err := GenerateKey(password)
if err != nil {
    t.Fatal(err)
}
privateKeyStr := initialKeyPair.PrivateKeyPem
publicKeyStr := initialKeyPair.PublicKeyDer
// can restore key pair string to file or database
fmt.Println("private key:\n", privateKeyStr)
fmt.Println("public key:\n", publicKeyStr)

key := EcKeyPair{
    PrivateKeyPem: privateKeyStr,
    PublicKeyDer:  publicKeyStr,
}

bodyToSign := []byte("hello world ( to sign )")
// sign data with private key and password
signature, err := key.PrivateSign(bodyToSign, password)
if err != nil {
    t.Fatal(err)
}
fmt.Println("sign result(hex):\n", hex.EncodeToString(signature))
// verify data with public key
res, err := key.PublicVerify(bodyToSign, signature)
if err != nil {
    t.Fatal(err)
}
if res == false {
    t.Fatal("verify failed!")
}

const newPassword = "!!123abc"
// modify private key password
_, err = key.ModifyPrivateKeyPassword(password, newPassword)
if err != nil {
    t.Fatal(err)
}
// old password should not work
signature2, err := key.PrivateSign(bodyToSign, password)
if err == nil {
    fmt.Println("sign result(hex):\n", hex.EncodeToString(signature2))
    t.Fatal("Error! old password works!")
}
// new password should work
signature3, err := key.PrivateSign(bodyToSign, newPassword)
if err != nil {
    t.Fatal(err)
}
fmt.Println("sign result(hex):\n", hex.EncodeToString(signature3))

```