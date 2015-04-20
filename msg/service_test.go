// Copyright (c) 2015 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package msg

import "testing"

func TestSplit255(t *testing.T) {
	xs := split255("abc")
	if len(xs) != 1 && xs[0] != "abc" {
		t.Logf("Failure to split abc")
		t.Fail()
	}
	s := ""
	for i := 0; i < 255; i++ {
		s += "a"
	}
	xs = split255(s)
	if len(xs) != 1 && xs[0] != s {
		t.Logf("failure to split 255 char long string")
		t.Logf("%s %v\n", s, xs)
		t.Fail()
	}
	s += "b"
	xs = split255(s)
	if len(xs) != 2 || xs[1] != "b" {
		t.Logf("failure to split 256 char long string: %d", len(xs))
		t.Logf("%s %v\n", s, xs)
		t.Fail()
	}
	for i := 0; i < 255; i++ {
		s += "a"
	}
	xs = split255(s)
	if len(xs) != 3 || xs[2] != "a" {
		t.Logf("failure to split 510 char long string: %d", len(xs))
		t.Logf("%s %v\n", s, xs)
		t.Fail()
	}
}

func TestGroup(t *testing.T) {
	sx := Group(
		[]Service{
			{Host: "server1", Group: "g1", Key: "region1.skydns.test."},
			{Host: "server2", Group: "g2", Key: "region1.skydns.test."},
		},
	)
	if len(sx) != 2 {
		t.Fatalf("failure to group first set: %v", sx)
	}

	sx = Group(
		[]Service{
			{Host: "server1", Group: "g1", Key: "a.dom.region1.skydns.test."},
			{Host: "server2", Group: "", Key: "b.dom.region1.skydns.test."},
			{Host: "server2", Group: "g1", Key: "b.subdom.region1.skydns.test."},
		},
	)
	if len(sx) != 3 {
		t.Fatalf("failure to group second set: %v", sx)
	}

	sx = Group(
		[]Service{
			{Host: "server1", Group: "g1", Key: "a.dom.region1.skydns.test."},
			{Host: "server2", Group: "", Key: "b.dom.region1.skydns.test."},
			{Host: "server2", Group: "g2", Key: "b.subdom.region1.skydns.test."},
		},
	)
	if len(sx) != 2 {
		t.Fatalf("failure to group third set: %v", sx)
	}
}
