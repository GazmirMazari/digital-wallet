package main

import (
	"digitalWallet/v3/wallet"
	"fmt"
	"log"
)

func init() {
	log.SetPrefix("Blockchain: ")
}

func main() {
	w := wallet.NewWallet()
	fmt.Println(w.PrivateKeyStr)
	fmt.Println(w.PublicKeyyftr)
}
