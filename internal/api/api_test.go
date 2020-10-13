package api

import (
	"testing"
)

func TestParsingUrl(t *testing.T) {
	path := "first/second/"
	exp := "second"
	_, remainingPath := ShiftPath(path)
	got, _ := ShiftPath(remainingPath)
	if got != exp {
		t.Errorf("Got: %v, Wanted: %v", got, exp)
	}
}

func TestNotEnoughSegments(t *testing.T) {
	path := "first/second/"
	exp := ""
	_, remainingPath := ShiftPath(path)
	_, remainingPath2 := ShiftPath(remainingPath)
	got, _ := ShiftPath(remainingPath2)
	if got != exp {
		t.Errorf("Got: %v, Wanted: %v", got, exp)
	}
}
