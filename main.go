package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"
)

// 检查文件路径是否存在
func fileExists(p string) bool {
	_, err := os.Stat(p)
	if err != nil {
		return false
	}
	return true
}

func main() {
	var generate, passwd, privateKeyPath, publicKeyPath, targetFile, signature string
	flag.StringVar(&generate, "g", "./", "生成秘钥对，指定目录")
	flag.StringVar(&passwd, "passwd", "", "私钥密码")
	flag.StringVar(&privateKeyPath, "pri", "", "私钥文件路径，签名时使用")
	flag.StringVar(&publicKeyPath, "pub", "", "公钥文件路径，验证时使用")
	flag.StringVar(&targetFile, "f", "", "需要生成签名/验签的文件")
	flag.StringVar(&signature, "s", "", "签名hex字符串")
	flag.Parse()
	//cur, _ := os.Getwd()

	args := flag.Args()
	var op string
	if len(args) == 0 {
		log.Fatalf("请指定命令")
	}
	op = args[0]

	//fmt.Println(*name, *age, *married, *delay)
	if op == "generate" {
		targetPath := path.Dir(generate)
		if _, err := os.Stat(targetPath); err == nil {
			err2 := os.MkdirAll(targetPath, 0744)
			if err2 != nil {
				log.Fatalf("创建指定文件夹失败！%s", targetPath)
			}
		}
		privateKeyName := "ec_private_key.pem"
		publicKeyName := "ec_public_key"

		privateKeyFullPath := path.Join(targetPath, privateKeyName)
		publicKeyFullPath := path.Join(targetPath, publicKeyName)
		if fileExists(privateKeyFullPath) {
			e2 := os.Remove(privateKeyFullPath)
			if e2 != nil {
				log.Fatalf("编辑私钥文件失败！")
			}
		}
		if fileExists(publicKeyFullPath) {
			e2 := os.Remove(publicKeyFullPath)
			if e2 != nil {
				log.Fatalf("编辑公钥文件失败！")
			}
		}
		keyObj, err := GenerateKey(passwd)
		if err != nil {
			log.Fatalf("生成秘钥对失败！")
		}
		err = os.WriteFile(privateKeyFullPath, []byte(keyObj.PrivateKeyPem), 400)
		if err != nil {
			log.Fatalf("编辑私钥文件失败！")
		}
		err = os.WriteFile(publicKeyFullPath, []byte(keyObj.PublicKeyDer), 400)
		if err != nil {
			log.Fatalf("编辑公钥文件失败！")
		}
		log.Println("秘钥对生成成功！")
		os.Exit(0)
	}
	var buf []byte
	f, _ := os.Stdin.Stat()
	if (f.Mode() & os.ModeNamedPipe) == os.ModeNamedPipe {
		buf, _ = io.ReadAll(os.Stdin)
	}
	if targetFile != "" {
		var err error
		buf, err = os.ReadFile(targetFile)
		if err != nil {
			log.Fatalf("read file error! %s", err)
		}
	}
	if op == "verify" {
		if publicKeyPath == "" || fileExists(publicKeyPath) == false {
			log.Fatalf("公钥文件不存在！")
		} else {
			key, err := os.ReadFile(publicKeyPath)
			if err != nil {
				log.Fatalf("read file error! %s", err)
			}
			keyPair := EcKeyPair{
				PublicKeyDer: string(key),
			}
			signatureBuf, _ := hex.DecodeString(signature)
			res, err := keyPair.PublicVerify(buf, signatureBuf)
			if res {
				fmt.Println("verify success!")
				os.Exit(0)
			} else {
				fmt.Println("verify failed!")
				os.Exit(1)
			}
		}
	} else if op == "sign" {
		if privateKeyPath == "" || fileExists(privateKeyPath) == false {
			log.Fatalf("私钥文件不存在！")
		} else {
			keyBuf, err := os.ReadFile(privateKeyPath)
			if err != nil {
				log.Fatalf("read file error! %s", err)
			}
			keyPair := EcKeyPair{
				PrivateKeyPem: string(keyBuf),
			}
			digest := sha256.New()
			digest.Write(buf)
			sign, err2 := keyPair.PrivateSign(digest.Sum(nil), passwd)
			if err2 != nil {
				log.Fatalf("sign error! %s", err2)
			} else {
				fmt.Println(hex.EncodeToString(sign))
			}
		}
	} else {
		flag.PrintDefaults()
	}

}
