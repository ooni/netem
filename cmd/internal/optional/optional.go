// Package optional allows to safely express optional values.
package optional

import "errors"

// Value is an optional value.
type Value[T any] struct {
	ok  bool
	val T
}

// None creates an empty optional value.
func None[T any]() Value[T] {
	return Value[T]{
		ok:  false,
		val: *new(T),
	}
}

// Some creates a non-empty optional value.
func Some[T any](val T) Value[T] {
	return Value[T]{
		ok:  true,
		val: val,
	}
}

// Empty returns whether the [Value] is empty.
func (v Value[T]) Empty() bool {
	return !v.ok
}

// ErrEmpty is the error passed to panic by [Value.Unwrap] when the value is empty.
var ErrEmpty = errors.New("optional: empty value")

// Unwrap panics if [Value] is empty, otherwise returns the underlying value.
func (v Value[T]) Unwrap() T {
	if !v.ok {
		panic(ErrEmpty)
	}
	return v.val
}
