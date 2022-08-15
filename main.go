package main

import (
  "crypto/aes"
  "log"
  "fmt"
  "crypto/rand"
  "encoding/binary"
)

const BITS_PER_BYTE = 8
const BYTES_PER_UINT64 = 64/BITS_PER_BYTE

func Dec(ct []byte, key []byte) []byte {
  block, err := aes.NewCipher(key)
  if err != nil {
    log.Fatal(err)
  }
  n := binary.LittleEndian.Uint64(ct)
  out := make([]byte, len(ct) - BYTES_PER_UINT64)
  copy(out, ct[BYTES_PER_UINT64:BYTES_PER_UINT64+aes.BlockSize])
  for i := aes.BlockSize; i < len(out); i += aes.BlockSize {
    block.Decrypt(out[i:], ct[BYTES_PER_UINT64+i:])
    for j := 0; j < aes.BlockSize; j++ {
      out[i+j] = out[i+j]^out[i+j-aes.BlockSize]
    }
  }
  return out[aes.BlockSize:aes.BlockSize+n]
}

func nearestBlockSize(n int) int {
  return n + aes.BlockSize - ((n-1)%aes.BlockSize) - 1
}

func Enc(pt []byte, key []byte) []byte {
  block, err := aes.NewCipher(key)
  if err != nil {
    log.Fatal(err)
  }
  IV := make([]byte, aes.BlockSize)
  rand.Read(IV)
  fmt.Println("IV:", IV)
  n := nearestBlockSize(len(pt)) + len(IV) + BYTES_PER_UINT64
  out := make([]byte, n)

  binary.LittleEndian.PutUint64(out, uint64(len(pt)))
  copy(out[BYTES_PER_UINT64:], IV)
  for i := BYTES_PER_UINT64 + len(IV); i < n; i += aes.BlockSize {
    xored := make([]byte, aes.BlockSize)
    copy(xored, out[i-aes.BlockSize:])
    fmt.Println("xored", xored)
    for j := 0; j < aes.BlockSize; j++ {
      pos := i+j-(BYTES_PER_UINT64 + len(IV))
      if pos < len(pt) {
        xored[j] = xored[j]^pt[pos]
      } else {
        b := make([]byte, 1)
        rand.Read(b)
        xored[j] = xored[j]^b[0]
      }
    }
    block.Encrypt(out[i:], xored)
  }
  return out
}

func main() {
  key := make([]byte, 16)
  ct := Enc([]byte{1,2,3}, key)
  fmt.Println(ct)
  dt := Dec(ct, key)
  fmt.Println(dt)
}
