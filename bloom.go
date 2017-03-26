// See https://fylux.github.io/2017/03/19/Bloom-Filter/ for a nice short
// conceptual overview of a Bloom Filter.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/willf/bitset"
)

type BloomFilter struct {
	size   uint           // Number of possible entries (m)
	hashes uint           // Number of hash functions (k)
	set    *bitset.BitSet // The bitset representing membership
}

func NewBloomFilter(size, hashes uint) *BloomFilter {
	return &BloomFilter{
		size:   size,
		hashes: hashes,
		set:    bitset.New(size),
	}
}

func hash(data []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(data)
	return hash.Sum64()
}

func (f *BloomFilter) index(i uint, hash uint64) uint {
	return (uint(hash) * i) % f.size
}

func (f *BloomFilter) CanContain(data []byte) bool {
	hash := hash(data)
	for i := uint(0); i < f.hashes; i++ {
		if !f.set.Test(f.index(i, hash)) {
			return false
		}
	}
	return true
}

func (f *BloomFilter) Add(data []byte) {
	hash := hash(data)
	for i := uint(0); i < f.hashes; i++ {
		f.set.Set(f.index(i, hash))
	}
}

func main() {
	bloom := NewBloomFilter(175000000, 30)
	table := make(map[uint64][]byte)
	list := make([][]byte, 2000000)

	// Read in the IP addresses from stdin.
	scanner := bufio.NewScanner(os.Stdin)
	hash := fnv.New64a()
	for scanner.Scan() {
		ip := net.ParseIP(scanner.Text())

		bloom.Add(ip)

		hash.Write(ip)
		table[hash.Sum64()] = ip
		hash.Reset()

		list = append(list, ip)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

	// Generate a random IP to look up in all data structures.
	rand.Seed(time.Now().UnixNano())
	buf := make([]byte, 4)
	rand.Read(buf)
	target := net.IPv4(buf[0], buf[1], buf[2], buf[3])

	var waitGroup sync.WaitGroup
	waitGroup.Add(3) // three goroutines

	// Time the Bloom Filter.
	go time("Bloom Filter", func() {
		bloom.CanContain(target)
	})

	// Time the hash table.
	go time("Hash table", func() {
		hash := fnv.New64a()
		hash.Write(target)
		if _, ok := table[hash.Sum64()]; ok {
		}
		hash.Reset()
	})

	// Time the list.
	go time("List", func() {
		for _, ip := range list {
			if bytes.Equal(ip, target) {
				break
			}
		}
	})

	waitGroup.Wait()
}

func sum(list []float64) float64 {
	var sum float64
	for _, i := range list {
		sum += i
	}
	return sum
}

func stddev(average float64, list []float64) float64 {
	var tmp float64
	for _, i := range list {
		tmp += (i - average) * (i - average)
	}

	variance := tmp / float64(len(list))
	return math.Sqrt(variance)
}

func time(name string, f func()) {
	latencies := make([]float64, 10)
	var begin time.Time
	var latency time.Duration
	for j := 0; j < 10; j++ {
		begin = time.Now()
		f()
		latency = time.Since(begin)
		latencies = append(latencies, latency.Seconds())
	}

	average := sum(latencies) / float64(len(latencies))
	fmt.Fprintf(os.Stdout,
		"%v: average latency: %v seconds, std dev: %v\n",
		name,
		average,
		stddev(average, latencies))
	waitGroup.Done()
}
