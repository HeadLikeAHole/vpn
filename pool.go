package main

import "sync"

type Pool[T any] struct {
	sync.Pool
}

func (p *Pool[T]) Get() *T {
	return p.Pool.Get().(*T)
}

func (p *Pool[T]) Put(v T) {
	p.Pool.Put(v)
}

func NewPool[T any](new func() T) *Pool[T] {
	return &Pool[T]{
		Pool: sync.Pool{
			New: func() any {
				return new()
			},
		},
	}
}
