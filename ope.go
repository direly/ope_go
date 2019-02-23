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

func sampleRange(min int64, max int64, coin func() int) int64 {

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

func genRandCoin(key []byte, iv int64) func() int {

	// make sure key length 256 bit
	if len(key) < 32 {
		padding := make([]byte, 32-len(key))
		key = append(key, padding...)
	}

	// aes block size 128bit
	aesBlock, _ := aes.NewCipher(key)
	p1 := uint64(iv)
	p2 := uint64(0)
	plainText := make([]byte, 16)
	cipherText := make([]byte, 16)
	binary.LittleEndian.PutUint64(plainText[:8], p1)
	binary.LittleEndian.PutUint64(plainText[8:], p2)
	aesBlock.Encrypt(cipherText, plainText)
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

func opeEncrypt(plainRangeL int64, plainRangeR int64, cipherRangeL int64, cipherRangeR int64, plain int64, key []byte) int64 {

	//fmt.Println(plainRangeL, plainRangeR, cipherRangeL, cipherRangeR, plain)

	if plainRangeL > plainRangeR {
		fmt.Fprintln(os.Stderr, "err: opeEncrypt plainRangeL > plainRangeR")
		return -1
	}
	if cipherRangeL > cipherRangeR {
		fmt.Fprintln(os.Stderr, "err: opeEncrypt cipherRangeL > cipherRangeR")
		return -1
	}
	if (plainRangeR - plainRangeL) > (cipherRangeR - cipherRangeL) {
		fmt.Fprintln(os.Stderr, "err: opeEncrypt plain range > cipher range")
		return -1
	}
	if plain > plainRangeR || plain < plainRangeL {
		fmt.Fprintln(os.Stderr, "err: opeEncrypt plain not in plain range")
		return -1
	}
	if (plainRangeR - plainRangeL) == (cipherRangeR - cipherRangeL) {
		return cipherRangeL + (plain - plainRangeL)
	}

	cipherMid := (cipherRangeL + cipherRangeR) / 2
	coin := genRandCoin(key, cipherMid)

	if plainRangeL == plainRangeR {
		return sampleRange(cipherRangeL, cipherRangeR, coin)
	}

	plainSampleRangeL := int64(0)
	plainSampleRangeR := int64(0)
	if plainRangeL+(cipherMid-cipherRangeL) < plainRangeR-1 {
		plainSampleRangeR = plainRangeL + (cipherMid - cipherRangeL)
	} else {
		plainSampleRangeR = plainRangeR - 1
	}
	if plainRangeL > plainRangeR-(cipherRangeR-cipherMid) {
		plainSampleRangeL = plainRangeL
	} else {
		plainSampleRangeL = plainRangeR - (cipherRangeR - cipherMid)
	}

	plainSampleResult := sampleRange(plainSampleRangeL, plainSampleRangeR, coin)
	if plain <= plainSampleResult {
		return opeEncrypt(plainRangeL, plainSampleResult, cipherRangeL, cipherMid, plain, key)
	} else {
		return opeEncrypt(plainSampleResult+1, plainRangeR, cipherMid+1, cipherRangeR, plain, key)
	}
}

func opeDecrypt(plainRangeL int64, plainRangeR int64, cipherRangeL int64, cipherRangeR int64, cipher int64, key []byte) int64 {

	//fmt.Println(plainRangeL, plainRangeR, cipherRangeL, cipherRangeR, cipher)

	if plainRangeL > plainRangeR {
		fmt.Fprintln(os.Stderr, "err: opeEncrypt plainRangeL > plainRangeR")
		return -1
	}
	if cipherRangeL > cipherRangeR {
		fmt.Fprintln(os.Stderr, "err: opeEncrypt cipherRangeL > cipherRangeR")
		return -1
	}
	if (plainRangeR - plainRangeL) > (cipherRangeR - cipherRangeL) {
		fmt.Fprintln(os.Stderr, "err: opeEncrypt plain range > cipher range")
		return -1
	}
	if cipher > cipherRangeR || cipher < cipherRangeL {
		fmt.Fprintln(os.Stderr, "err: opeEncrypt plain not in plain range")
		return -1
	}
	if (plainRangeR - plainRangeL) == (cipherRangeR - cipherRangeL) {
		return plainRangeL + (cipher - cipherRangeL)
	}

	cipherMid := (cipherRangeL + cipherRangeR) / 2
	coin := genRandCoin(key, cipherMid)

	if plainRangeL == plainRangeR {
		testResult := sampleRange(cipherRangeL, cipherRangeR, coin)
		if cipher == testResult {
			return plainRangeL
		} else {
			fmt.Fprintln(os.Stderr, "err: not a valid cipher")
			return -1
		}
	}

	plainSampleRangeL := int64(0)
	plainSampleRangeR := int64(0)
	if plainRangeL+(cipherMid-cipherRangeL) < plainRangeR-1 {
		plainSampleRangeR = plainRangeL + (cipherMid - cipherRangeL)
	} else {
		plainSampleRangeR = plainRangeR - 1
	}
	if plainRangeL > plainRangeR-(cipherRangeR-cipherMid) {
		plainSampleRangeL = plainRangeL
	} else {
		plainSampleRangeL = plainRangeR - (cipherRangeR - cipherMid)
	}

	plainSampleResult := sampleRange(plainSampleRangeL, plainSampleRangeR, coin)
	if cipher <= cipherMid {
		return opeDecrypt(plainRangeL, plainSampleResult, cipherRangeL, cipherMid, cipher, key)
	} else {
		return opeDecrypt(plainSampleResult+1, plainRangeR, cipherMid+1, cipherRangeR, cipher, key)
	}
}

func main() {

	fmt.Println(os.Args)

	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "-e":
		plainRangeL := int64(0)
		plainRangeR, _ := strconv.ParseInt(os.Args[2], 0, 32)
		cipherRangeL := int64(0)
		cipherRangeR, _ := strconv.ParseInt(os.Args[3], 0, 32)
		plain, _ := strconv.ParseInt(os.Args[4], 0, 32)
		key, _ := hex.DecodeString(os.Args[5])

		if plainRangeR > cipherRangeR {
			fmt.Fprintln(os.Stderr, "err: plain range > cipher range")
		}

		cipher := opeEncrypt(plainRangeL, plainRangeR, cipherRangeL, cipherRangeR, plain, key)
		fmt.Println(cipher)

	case "-d":
		plainRangeL := int64(0)
		plainRangeR, _ := strconv.ParseInt(os.Args[2], 0, 32)
		cipherRangeL := int64(0)
		cipherRangeR, _ := strconv.ParseInt(os.Args[3], 0, 32)
		cipher, _ := strconv.ParseInt(os.Args[4], 0, 32)
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

	case "-t0":
		key := make([]byte, 32)
		rand.Read(key)
		coin := genRandCoin(key, 999)
		resMap := make(map[int64]int)
		for i := 0; i < 100000; i++ {
			x := sampleRange(0, 3, coin)
			_, ok := resMap[x]
			if ok {
				resMap[x]++
			} else {
				resMap[x] = 1
			}
		}
		fmt.Println(resMap)

	case "-t1":
		key, _ := hex.DecodeString("3930ed2ff0d28ae5404e1eef2d60643b1135ad3c84da0f0ad99a9695775bd43c")
		for i := int64(0); i <= 100; i++ {
			en := opeEncrypt(0, 100, 0, 1000, i, key)
			de := opeDecrypt(0, 100, 0, 1000, en, key)
			fmt.Println("test result: ", i, en, de)
		}

	case "-h":
		printUsage()
	}

}
