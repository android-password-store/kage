// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import (
	"encoding/base64"

	"c2sp.org/CCTV/age/internal/testkit"
)

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.X25519(testkit.TestX25519Recipient)
	body, _ := base64.RawStdEncoding.DecodeString(f.UnreadLine())
	body[len(body)-1] ^= 0xff
	f.TextLine(base64.RawStdEncoding.EncodeToString(body))
	f.HMAC()
	f.Payload("age")
	f.ExpectNoMatch()
	f.Comment("the ChaCha20Poly1305 authentication tag on the body of the X25519 stanza is wrong")
	f.Generate()
}
