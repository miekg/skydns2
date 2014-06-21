// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

// LRU cache that holds RRs and for DNSSEC an RRSIG.

import (
	"container/list"
	"crypto/sha1"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Elem hold an answer and additional section that returned from the cache.
// The signature is put in answer, extra is empty there. This wastes some memory.
type Elem struct {
	key        string
	expiration time.Time // time added + TTL, after this the elem is invalid
	answer     []dns.RR
	extra      []dns.RR
}

type cache struct {
	sync.RWMutex
	l        *list.List
	m        map[string]*list.Element
	capacity uint // number of RRs
	size     uint // current size
	ttl	 time.Duration  // ttl use the storing messages
}

// TODO(miek): add setCapacity so it can be set runtime.

func NewCache(capacity, ttl int) *cache {
	c := new(cache)
	c.l = list.New()
	c.m = make(map[string]*list.Element)
	c.capacity = uint(capacity)
	c.ttl = time.Duration(ttl) * time.Second
	return c
}

func (c *cache) Remove(s string) {
	c.Lock()
	defer c.Unlock()
	e := c.m[s]
	if e == nil {
		return
	}
	c.size -= 1
	c.l.Remove(e)
	delete(c.m, s)
	c.shrink()
}

func (c *cache) shrink() {
	for c.size > c.capacity {
		e := c.l.Back()
		if e == nil { // nothing left
			break
		}
		v := e.Value.(*Elem)
		c.l.Remove(e)
		delete(c.m, v.key)
		c.size -= uint(len(v.answer) + len(v.extra))
	}
}

// insertMsg inserts a message in the cache. We will cahce it for ttl seconds, which
// should be a small (60...300) integer.
func (c *cache) InsertMsg(s string, answer, extra []dns.RR) {
	if c.capacity == 0 {
		return
	}
	c.Lock()
	defer c.Unlock()
	if _, ok := c.m[s]; !ok {
		e := c.l.PushFront(&Elem{s, time.Now().UTC().Add(time.Second * c.ttl), answer, extra})
		c.m[s] = e
	}
	c.size += uint(len(answer) + len(extra))
	c.shrink()
}

// insertSig inserts a signature, the expiration time is used as the cache ttl.
func (c *cache) InsertSig(s string, sig *dns.RRSIG) {
	if c.capacity == 0 {
		return
	}
	c.Lock()
	defer c.Unlock()
	if _, ok := c.m[s]; !ok {
		// TODO(miek): FIX expiration
		e := c.l.PushFront(&Elem{s, time.Now().UTC().Add(time.Second * 5), []dns.RR{sig}, nil})
		c.m[s] = e
	}
	c.size += 1
	c.shrink()
}

func (c *cache) Search(s string) ([]dns.RR, []dns.RR) {
	if c.capacity == 0 {
		return nil, nil
	}
	c.RLock()
	defer c.RUnlock()
	if e, ok := c.m[s]; ok {
		// we want to return a copy here, because if we didn't the RRSIG
		// could be removed by another goroutine before the packet containing
		// this signature is send out.
		c.l.MoveToFront(e)
		e := e.Value.(*Elem)
		answer := make([]dns.RR, len(e.answer))
		extra := make([]dns.RR, len(e.extra))
		for i, r := range e.answer {
			answer[i] = dns.Copy(r)
		}
		for i, r := range e.extra {
			extra[i] = dns.Copy(r)
		}
		return answer, extra
	}
	return nil, nil
}

func QuestionKey(q dns.Question) string {
	h := sha1.New()
	i := append([]byte(q.Name), packUint16(q.Qtype)...)
	return string(h.Sum(i))
}


// key uses the name, type and rdata, which is serialized and then hashed as the
// key for the lookup
func (c *cache) Key(rrs []dns.RR) string {
	h := sha1.New()
	i := []byte(rrs[0].Header().Name)
	i = append(i, packUint16(rrs[0].Header().Rrtype)...)
	for _, r := range rrs {
		switch t := r.(type) { // we only do a few type, serialize these manually
		case *dns.SOA:
			// We only fiddle with the serial so store that.
			i = append(i, packUint32(t.Serial)...)
		case *dns.SRV:
			i = append(i, packUint16(t.Priority)...)
			i = append(i, packUint16(t.Weight)...)
			i = append(i, packUint16(t.Weight)...)
			i = append(i, []byte(t.Target)...)
		case *dns.A:
			i = append(i, []byte(t.A)...)
		case *dns.AAAA:
			i = append(i, []byte(t.AAAA)...)
		case *dns.NSEC3:
			i = append(i, []byte(t.NextDomain)...)
			// Bitmap does not differentiate in SkyDNS.
		case *dns.DNSKEY:
		case *dns.NS:
		case *dns.TXT:
		}
	}
	return string(h.Sum(i))
}

func packUint16(i uint16) []byte { return []byte{byte(i >> 8), byte(i)} }
func packUint32(i uint32) []byte { return []byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)} }
