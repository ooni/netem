package netem

// Must0 panics in case of error
func Must0(err error) {
	if err != nil {
		panic(err)
	}
}

// Must1 panics in case of error otherwise returns the first value
func Must1[Type any](value Type, err error) Type {
	Must0(err)
	return value
}

// Must2 panics in case of error otherwise returns the two values
func Must2[A, B any](a A, b B, err error) (A, B) {
	Must0(err)
	return a, b
}
