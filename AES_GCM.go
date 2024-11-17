package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

func findPassword() {
	nonce := make([]byte, 12)
	data := "jwang34@iit.edu"

	ciphermac, _ := hex.DecodeString(
		"2d793bb434787e88d1db0f27453ac971149a6d3138591f8fa84e133805bfc748dbe9cc10d6ab7ce5b53e0b2dff6e")

	fmt.Printf("finding password for nonce=%x, data=%s, ciphermac=%x...\n",
		nonce, data, ciphermac)

	for i := 0; i < 10000; i++ {
		password := fmt.Sprintf("%04d", i)

		sha := sha256.New()
		sha.Write([]byte(password))
		key := sha.Sum(nil)

		block, err := aes.NewCipher(key)
		if err != nil {
			continue
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}

		plaintext, err := aesgcm.Open(nil, nonce, ciphermac, []byte(data))
		if err == nil {
			fmt.Printf("  correct password=%s\n", password)
			fmt.Printf("  plaintext=%s\n", string(plaintext))
			break
		}
		if false {
			fmt.Printf("  correct password=%s\n", password)
			break
		}
	}
}

func timedeko() {
	msg := "1029384756abcdef"

	fmt.Printf(msg)
	start := time.Now()

	sha := sha256.New()
	sha.Write([]byte(msg))
	hash := sha.Sum(nil)

	duration := time.Since(start)

	fmt.Printf(hex.EncodeToString(hash))
	fmt.Printf("time taken : %d ns\n", duration.Nanoseconds())
}

func onembtime() {
	msg := make([]byte, 1024*1024)
	rand.Read(msg)

	key := make([]byte, 32)
	rand.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	rand.Read(nonce)

	start := time.Now()
	ciphertext := aesgcm.Seal(nil, nonce, msg, nil)
	duration := time.Since(start)

	start2 := time.Now()
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	duration2 := time.Since(start2)

	fmt.Printf("time taken for encryption: %d ns\n", duration)
	fmt.Printf("ciphertext size : %d bytes\n", len(ciphertext))
	fmt.Printf("time taken for decryption: %d ns\n", duration2)
	fmt.Printf("plaintext size : %d bytes\n", len(plaintext))
}

func main() {
	findPassword()
	timedeko()
	onembtime()
}
