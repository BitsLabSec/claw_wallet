package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"sandbox/internals/signer"
)

func main() {
	pin := flag.String("pin", "phase2-fixture-pin", "PIN used to encrypt generated shares")
	flag.Parse()

	tempSigner := &signer.Signer{}
	res, err := tempSigner.CreateWallet(*pin)
	if err != nil {
		log.Fatalf("failed to create fixture wallet: %v", err)
	}

	out, err := json.MarshalIndent(map[string]any{
		"uid":            res.UID,
		"master_pub_key": res.MasterPubKey,
		"address":        res.Address,
		"addresses":      res.Addresses,
		"enc_share1":     res.Share1,
		"enc_share2":     res.Share2,
		"enc_share3":     res.Share3,
	}, "", "  ")
	if err != nil {
		log.Fatalf("failed to encode fixture output: %v", err)
	}
	fmt.Println(string(out))
}
