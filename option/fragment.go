package option

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

type TLSFragmentOptions struct {
	Enabled bool   `json:"enabled,omitempty"`
	Size    string `json:"size,omitempty"`  // Fragment size in Bytes
	Sleep   string `json:"sleep,omitempty"` // Time to sleep between sending the fragments in milliseconds
}

func ParseIntRange(str string) ([]int, error) {
	if str == "" {
		return nil, E.New("Empty input")
	}
	
	splitString := strings.Split(str, "-")
	s, err := strconv.ParseInt(splitString[0], 10, 32)
	if err != nil {
		return nil, E.Cause(err, "error parsing string to integer")
	}
	e := s
	if len(splitString) == 2 {
		e, err = strconv.ParseInt(splitString[1], 10, 32)
		if err != nil {
			return nil, E.Cause(err, "error parsing string to integer")
		}

	}
	if s < 0 {
		return nil, E.Cause(E.New(fmt.Sprintf("Negative value (%d) is not possible", s)), "invalid range")
	}
	if e < s {
		return nil, E.Cause(E.New(fmt.Sprintf("upper bound value (%d) must be greater than or equal to lower bound value (%d)", e, s)), "invalid range")
	}
	return []int{int(s), int(e)}, nil

}

func RandBetween(min int, max int) int {
	if max == min {
		return min
	}
	return rand.Intn(max-min+1) + min

}
