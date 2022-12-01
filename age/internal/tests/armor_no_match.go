// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import "c2sp.org/CCTV/age/internal/testkit"

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	identity := f.Rand(32)
	f.X25519RecordIdentity(identity)
	f.X25519NoRecordIdentity(testkit.TestX25519Recipient)
	f.HMAC()
	f.Payload("age")
	f.ExpectNoMatch()
	file := f.Bytes()
	f.Buf.Reset()
	f.BeginArmor("AGE ENCRYPTED FILE")
	f.Body(file)
	f.Base64Padding()
	f.EndArmor("AGE ENCRYPTED FILE")
	f.Generate()
}
