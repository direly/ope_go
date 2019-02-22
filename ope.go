package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
)

func printUsage() {

	fmt.Printf("Usage: %s -[e|d|g|h]\n", os.Args[0])
	fmt.Printf("       %s -e plain_range cipher_range plain key: encrypt\n", os.Args[0])
	fmt.Printf("       %s -d plain_range cipher_range cipher key: decrypt\n", os.Args[0])
	fmt.Printf("       %s -g: generate rand key\n", os.Args[0])
	fmt.Printf("       %s -h: print help info\n", os.Args[0])
}

func sampleRange(min uint64, max uint64, coin func() int) uint64 {

	if min > max {
		return 0
	}

	for min < max {
		if 0 == coin() {
			max = (min + max) / 2
		} else {
			min = (min+max)/2 + 1
		}
	}

	return min
}

func genRandCoin(key []byte, iv uint64) func() int {

	// make sure key length 256 bit
	if len(key) < 32 {
		padding := make([]byte, 32-len(key))
		key = append(key, padding...)
	}

	// aes block size 128bit
	aesBlock, _ := aes.NewCipher(key)
	p1 := iv
	p2 := uint64(0)
	plainText := make([]byte, 16)
	cipherText := make([]byte, 16)
	cursor := uint64(0)

	return func() int {

		if cursor == 128 {
			p1++
			if p1 == 0 {
				p2++
			}
			cursor = 0

			binary.LittleEndian.PutUint64(plainText[:8], p1)
			binary.LittleEndian.PutUint64(plainText[8:], p2)
			aesBlock.Encrypt(cipherText, plainText)
		}

		cursor1 := cursor / 8
		cursor2 := cursor % 8
		coin := int(0)
		if cipherText[cursor1]&(1<<cursor2) > 0 {
			coin = 1
		} else {
			coin = 0
		}
		cursor++
		return coin
	}

}

func opeEncrypt(plainRangeL uint64, plainRangeR uint64, cipherRangeL uint64, cipherRangeR uint64, plain uint64, key []byte) uint64 {

	if plainRangeL > plainRangeR {
		fmt.Fprintln(os.Stderr, "err: opeEncrypt plainRangeL > plainRangeR")
		return 0
	}
	if cipherRangeL > cipherRangeR {
		fmt.Fprintln(os.Stderr, "err: opeEncrypt cipherRangeL > cipherRangeR")
		return 0
	}
	if (plainRangeR - plainRangeL) > (cipherRangeR - cipherRangeL) {
		fmt.Fprintln(os.Stderr, "err: opeEncrypt plain range > cipher range")
		return 0
	}
	if plain > plainRangeR || plain < plainRangeL {
		fmt.Fprintln(os.Stderr, "err: opeEncrypt plain not in plain range")
		return 0
	}
	if (plainRangeR - plainRangeL) == (cipherRangeR - cipherRangeL) {
		return cipherRangeR + (plain - plainRangeL)
	}

	cipherMid := (cipherRangeL + cipherRangeR) / 2
	coin := genRandCoin(key, cipherMid)

	plainSampleRangeL := plainRangeL
	plainSampleRangeR := plainRangeR
	if cipherMid-cipherRangeL < plainRangeR-plainRangeL {
		plainSampleRangeR = plainRangeL + (cipherMid - cipherRangeL)
	}
	if cipherRangeR-cipherMid < plainRangeR-plainRangeL {
		plainSampleRangeL = plainRangeR - (cipherRangeR - cipherMid)
	}

	plainSample := sampleRange(plainSampleRangeL, plainSampleRangeR, coin)

	return 0
}

func opeDecrypt(plainRangeL uint64, plainRangeR uint64, cipherRangeL uint64, cipherRangeR uint64, plain uint64, key []byte) uint64 {
	return 0
}

func main() {

	fmt.Println(os.Args)

	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "-e":
		plainRangeL := uint64(0)
		plainRangeR, _ := strconv.ParseUint(os.Args[2], 0, 32)
		cipherRangeL := uint64(0)
		cipherRangeR, _ := strconv.ParseUint(os.Args[3], 0, 32)
		plain, _ := strconv.ParseUint(os.Args[4], 0, 32)
		key, _ := hex.DecodeString(os.Args[5])

		if plainRangeR > cipherRangeR {
			fmt.Fprintln(os.Stderr, "err: plain range > cipher range")
		}

		cipher := opeEncrypt(plainRangeL, plainRangeR, cipherRangeL, cipherRangeR, plain, key)
		fmt.Println(cipher)

	case "-d":
		plainRangeL := uint64(0)
		plainRangeR, _ := strconv.ParseUint(os.Args[2], 0, 32)
		cipherRangeL := uint64(0)
		cipherRangeR, _ := strconv.ParseUint(os.Args[3], 0, 32)
		cipher, _ := strconv.ParseUint(os.Args[4], 0, 32)
		key, _ := hex.DecodeString(os.Args[5])

		if plainRangeR > cipherRangeR {
			fmt.Fprintln(os.Stderr, "err: plain range > cipher range")
		}

		plain := opeDecrypt(plainRangeL, plainRangeR, cipherRangeL, cipherRangeR, cipher, key)
		fmt.Println(plain)

	case "-g":
		// 32byte for 256bit
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			fmt.Fprintln(os.Stderr, "err: failed to generate random key")
		}
		fmt.Println("random key(256bit):")
		fmt.Println(hex.EncodeToString(key))

	case "-t":
		key := make([]byte, 32)
		rand.Read(key)
		coin := genRandCoin(key, 999)
		resMap := make(map[uint64]int)
		for i := 0; i < 1000000; i++ {
			x := sampleRange(3, 10, coin)
			_, ok := resMap[x]
			if ok {
				resMap[x]++
			} else {
				resMap[x] = 1
			}
		}
		fmt.Println(resMap)

	case "-h":
		printUsage()
	}

}
