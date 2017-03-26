package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBloomFilter(t *testing.T) {
	bloom := NewBloomFilter(uint(^uint16(0)), 30)
	bloom.Add([]byte("ever"))
	bloom.Add([]byte("rain"))
	bloom.Add([]byte("have"))

	assert := assert.New(t)
	assert.Equal(true, bloom.CanContain([]byte("ever")))
	assert.Equal(true, bloom.CanContain([]byte("rain")))
	assert.Equal(true, bloom.CanContain([]byte("have")))

	assert.Equal(false, bloom.CanContain([]byte("seen")))
	assert.Equal(false, bloom.CanContain([]byte("you")))
}
