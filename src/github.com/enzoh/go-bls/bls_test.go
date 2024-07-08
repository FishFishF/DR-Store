/**
 * File        : bls_test.go
 * Description : Unit tests.
 * Copyright   : Copyright (c) 2017-2018 DFINITY Stiftung. All rights reserved.
 * Maintainer  : Enzo Haussecker <enzo@dfinity.org>
 * Stability   : Stable
 *
 * This module provides unit tests for the Boneh-Lynn-Shacham signature scheme.
 */

package bls

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestSignVerify(test *testing.T) {

	message := "This is a message."

	// Generate a key pair.
	params := GenParamsTypeA(160, 512)
	pairing := GenPairing(params)
	system, err := GenSystem(pairing)
	if err != nil {
		test.Fatal(err)
	}
	key, secret, err := GenKeys(system)
	if err != nil {
		test.Fatal(err)
	}

	// Sign the message.
	hash := sha256.Sum256([]byte(message))
	signature := Sign(hash, secret)

	// Verify the signature.
	if !Verify(signature, hash, key) {
		test.Fatal("Failed to verify signature.")
	}

	// Clean up.
	signature.Free()
	key.Free()
	secret.Free()
	system.Free()
	pairing.Free()
	params.Free()

}

func TestAggregateVerify(test *testing.T) {

	messages := []string{
		"This is a message.",
		"This is another message.",
		"This is yet another message.",
		"These messages are unique.",
	}
	n := len(messages)

	// Generate key pairs.
	params, err := GenParamsTypeD(9563, 512)
	if err != nil {
		test.Fatal(err)
	}
	pairing := GenPairing(params)
	system, err := GenSystem(pairing)
	if err != nil {
		test.Fatal(err)
	}
	keys := make([]PublicKey, n)
	secrets := make([]PrivateKey, n)
	for i := 0; i < n; i++ {
		keys[i], secrets[i], err = GenKeys(system)
		if err != nil {
			test.Fatal(err)
		}
	}

	// Sign the messages.
	hashes := make([][sha256.Size]byte, n)
	signatures := make([]Signature, n)
	for i := 0; i < n; i++ {
		hashes[i] = sha256.Sum256([]byte(messages[i]))
		signatures[i] = Sign(hashes[i], secrets[i])
	}

	// Aggregate the signatures.
	aggregate, err := Aggregate(signatures, system)
	if err != nil {
		test.Fatal(err)
	}

	// Verify the aggregate signature.
	valid, err := AggregateVerify(aggregate, hashes, keys)
	if err != nil {
		test.Fatal(err)
	}
	if !valid {
		test.Fatal("Failed to verify aggregate signature.")
	}

	// Clean up.
	aggregate.Free()
	for i := 0; i < n; i++ {
		signatures[i].Free()
		keys[i].Free()
		secrets[i].Free()
	}
	system.Free()
	pairing.Free()
	params.Free()

}

func TestThresholdSignature(test *testing.T) {

	//message := "This is a message."
	data := make([]byte, 10240000)
	_, err := rand.Read(data)
	if err != nil {
		fmt.Println("随机数据生成失败:", err)
		return
	}

	fmt.Println("len", len(data))
	// Generate key shares.

	params := GenParamsTypeF(256)
	pairing := GenPairing(params)
	system, err := GenSystem(pairing)
	if err != nil {
		test.Fatal(err)
	}
	rand.Seed(time.Now().UnixNano())
	n := 40
	t := 28
	groupKey, memberKeys, groupSecret, memberSecrets, err := GenKeyShares(t, n, system)
	if err != nil {
		test.Fatal(err)
	}

	// Select group members.
	memberIds := rand.Perm(n)[:t]

	// Sign the message.
	hash := sha256.Sum256(data)
	shares := make([]Signature, t)
	d3 := time.Now()
	for i := 0; i < t; i++ {

		shares[i] = Sign(hash, memberSecrets[memberIds[i]])
		fmt.Println(shares[i])

	}
	d4 := time.Now()
	fmt.Println("Sign", d4.Sub(d3))

	// Recover the threshold signature.
	// shares = shares[10:]
	// memberIds = memberIds[10:]
	fmt.Println(shares)
	fmt.Println(memberIds)

	signature, err := Threshold(shares, memberIds, system)

	if err != nil {
		test.Fatal(err)
	}

	// Verify the threshold signature.

	if !Verify(signature, hash, groupKey) {
		test.Fatal("Failed to verify signature.")
	}
	d1 := time.Now()
	Verify(signature, hash, groupKey)
	d2 := time.Now()
	fmt.Println(d2.Sub(d1))
	// Clean up.
	signature.Free()
	groupKey.Free()
	groupSecret.Free()
	for i := 0; i < t; i++ {
		shares[i].Free()
	}
	for i := 0; i < n; i++ {
		memberKeys[i].Free()
		memberSecrets[i].Free()
	}
	system.Free()
	pairing.Free()
	params.Free()

}

func TestToFromBytes(test *testing.T) {

	message := "This is a message."

	// Generate a key pair.
	params := GenParamsTypeA(160, 512)
	pairing := GenPairing(params)
	system, err := GenSystem(pairing)
	if err != nil {
		test.Fatal(err)
	}
	key, secret, err := GenKeys(system)
	if err != nil {
		test.Fatal(err)
	}

	// Sign the message and serialize the signature.
	hash := sha256.Sum256([]byte(message))
	signatureOut := Sign(hash, secret)
	bytes := system.SigToBytes(signatureOut)

	// Deserialize the signature and verify it.
	signatureIn, err := system.SigFromBytes(bytes)
	if err != nil {
		test.Fatal(err)
	}
	if !Verify(signatureIn, hash, key) {
		test.Fatal("Failed to verify signature.")
	}

	// Clean up.
	signatureIn.Free()
	signatureOut.Free()
	key.Free()
	secret.Free()
	system.Free()
	pairing.Free()
	params.Free()

}

func BenchmarkVerify(benchmark *testing.B) {

	message := "This is a message."

	// Generate a key pair.
	params := GenParamsTypeF(160)
	pairing := GenPairing(params)
	system, err := GenSystem(pairing)
	if err != nil {
		benchmark.Fatal(err)
	}
	key, secret, err := GenKeys(system)
	if err != nil {
		benchmark.Fatal(err)
	}

	// Sign the message.
	hash := sha256.Sum256([]byte(message))
	signature := Sign(hash, secret)

	// Verify the signature.
	benchmark.StartTimer()
	for i := 0; i < benchmark.N; i++ {
		Verify(signature, hash, key)
	}
	benchmark.StopTimer()

	// Clean up.
	signature.Free()
	key.Free()
	secret.Free()
	system.Free()
	pairing.Free()
	params.Free()

}
