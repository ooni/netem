package main

import "testing"

func TestMainStar(t *testing.T) {
	starMu.Lock()
	oldFlagValue := *starFlag
	*starFlag = true
	starMu.Unlock()

	main()

	defer func() {
		starMu.Lock()
		*starFlag = oldFlagValue
		starMu.Unlock()
	}()
}

func TestMainPPP(t *testing.T) {
	starMu.Lock()
	oldFlagValue := *starFlag
	*starFlag = false
	starMu.Unlock()

	main()

	defer func() {
		starMu.Lock()
		*starFlag = oldFlagValue
		starMu.Unlock()
	}()
}
