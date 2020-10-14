package api

import (
	"errors"
	"time"
)

type TimeJ struct {
	time.Time
}

// Format time as RFC3339 instead of RFC3339Nano which PHP does not support.
// Based on MarshalJSON from time.go, changed RFC3339Nano to RFC3339.
// MarshalJSON implements the json.Marshaler interface.
// The time is a quoted string in RFC 3339 format.
func (t TimeJ) MarshalJSON() ([]byte, error) {
	if y := t.Year(); y < 0 || y >= 10000 {
		// RFC 3339 is clear that years are 4 digits exactly.
		// See golang.org/issue/4556#c15 for more discussion.
		return nil, errors.New("Time.MarshalJSON: year outside of range [0,9999]")
	}

	const surroundingQuotesLen = 2
	b := make([]byte, 0, len(time.RFC3339)+surroundingQuotesLen)
	b = append(b, '"')
	b = t.AppendFormat(b, time.RFC3339)
	b = append(b, '"')
	return b, nil
}
