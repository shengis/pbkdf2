package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"crypto/sha1"
	"golang.org/x/crypto/pbkdf2"
)

type Params struct {
	iter int
	keylen int
	content string
	salt string
}

func setInt(t *int, s string, field string) error {
	if tmp, err := strconv.Atoi(s); err != nil {
		return errors.New(field + " must be a number")
	} else {
		*t = tmp
	}

	return nil
}

func (p *Params) Parse() error {
	if len(os.Args) <= 2 {
		return errors.New("Not enough arguments")
	}

	// Default parameters
	p.iter = 4096
	p.keylen = 16

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-i":
			i++
			if err := setInt(&p.iter, os.Args[i], "iter"); err != nil {
				return err
			}

		case "-n":
			i++
			if err := setInt(&p.keylen, os.Args[i], "keylen"); err != nil {
				return err
			}

		default:
			if p.content == "" {
				p.content = os.Args[i]
			} else if p.salt == "" {
				p.salt = os.Args[i]
			} else {
				return errors.New("Argument not recognized")
			}
		}
	}

	if p.content == "" {
		return errors.New("Parameter 'content' is not set")
	}

	if p.salt == "" {
		return errors.New("Parameter 'salt' is not set")
	}

	return nil
}

func Encrypt(content string, salt string, iter int, keylen int) {
	fmt.Printf("%x", pbkdf2.Key([]byte(content), []byte(salt), iter, keylen, sha1.New))
}

func main() {
	var params Params

	if err := params.Parse(); err != nil {
		fmt.Println(err)
		fmt.Println("")
		fmt.Println("Usage:")
		fmt.Println(" " + os.Args[0] + " [Options] content salt")
		fmt.Println("")
		fmt.Println("Options:")
		fmt.Println(" -i <iterations>  Number of iterations")
		fmt.Println(" -n <keylen>      Result key length")
		fmt.Println("")
		os.Exit(1)
	}

	Encrypt(params.content, params.salt, params.iter, params.keylen)
}
