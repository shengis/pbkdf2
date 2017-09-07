package main

import (
	"crypto/sha1"
	"fmt"
	"os"
	"golang.org/x/crypto/pbkdf2"
)

func Encrypt(content string, salt string) {
	fmt.Printf("%x", pbkdf2.Key([]byte(content), []byte(salt), 4096, 16, sha1.New))
}

func main() {
	if len(os.Args) == 3 {
		Encrypt(os.Args[1], os.Args[2])
	} else {
		fmt.Printf("USAGE: pbkdf2 PASSWORD SALT")
	}
}
