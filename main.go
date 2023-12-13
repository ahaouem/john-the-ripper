package main

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/sha3"
)

type Hasher interface {
	Hash(input string) string
}

type SHA256Hasher struct{}

func (s *SHA256Hasher) Hash(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

type SHA3Hasher struct{}

func (s *SHA3Hasher) Hash(input string) string {
	h := sha3.New512()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

type MD5Hasher struct{}

func (m *MD5Hasher) Hash(input string) string {
	h := md5.New()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func main() {
	targetHash := os.Args[1]
	wordlistPath := os.Args[2]

	wordlist, err := os.ReadFile(wordlistPath)
	if err != nil {
		fmt.Println("Error reading wordlist:", err)
		os.Exit(1)
	}

	passwords := strings.Split(string(wordlist), "\n")

	hashers := []Hasher{
		&SHA256Hasher{},
		&SHA3Hasher{},
		&MD5Hasher{},
	}

	for _, password := range passwords {
		password = strings.TrimSpace(password)

		if checkPassword(password, targetHash, hashers) {
			fmt.Printf("Found password: \"%s\"\n", password)
			return
		}
	}

	fmt.Println("Password not found in the wordlist.")
}

func checkPassword(password, targetHash string, hashers []Hasher) bool {
	for _, hasher := range hashers {
		hashedPassword := hasher.Hash(password)
		if hashedPassword == targetHash {
			return true
		}
	}

	return false
}
