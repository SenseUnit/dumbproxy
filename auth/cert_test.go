package auth

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func mkbytes(l uint) []byte {
	b := make([]byte, l)
	for i := uint(0); i < l; i++ {
		b[i] = byte(i)
	}
	return b
}

var mask *big.Int = big.NewInt(0).Add(big.NewInt(0).Lsh(big.NewInt(1), uint(8*len(serialNumberKey{}))), big.NewInt(-1))

func TestNormalizeSNBytes(t *testing.T) {
	for i := uint(0); i <= 32; i++ {
		t.Run(fmt.Sprintf("%d-bytes", i), func(t *testing.T) {
			s := mkbytes(i)
			k := normalizeSNBytes(s)
			var a, b big.Int
			a.SetBytes(s).And(&a, mask)
			b.SetBytes(k[:])
			if a.Cmp(&b) != 0 {
				t.Fatalf("%d != %d", &a, &b)
			}
		})
	}
}

type parseSerialBytesTestcase struct {
	input  []byte
	output []byte
	error  bool
}

func TestParseSerialBytes(t *testing.T) {
	testcases := []parseSerialBytesTestcase{
		{
			input:  []byte(""),
			output: []byte{},
		},
		{
			input:  []byte("01:02:03"),
			output: []byte{1, 2, 3},
		},
		{
			input:  []byte("ff"),
			output: []byte{255},
		},
		{
			input: []byte("ff:f"),
			error: true,
		},
		{
			input: []byte("f"),
			error: true,
		},
		{
			input: []byte("fff"),
			error: true,
		},
		{
			input: []byte("---"),
			error: true,
		},
	}
	for i, testcase := range testcases {
		t.Run(fmt.Sprintf("Testcase[%d]", i), func(t *testing.T) {
			out, err := parseSerialBytes(testcase.input)
			if (err != nil) != testcase.error {
				t.Fatalf("unexpected error: %v", err)
			}
			if bytes.Compare(out, testcase.output) != 0 {
				t.Fatalf("expected %v, got %v", testcase.output, out)
			}
		})
	}
}

type serialNumberSetTestcase struct {
	input  *big.Int
	output bool
}

func TestSerialNumberSetSmoke(t *testing.T) {
	const testFile = `
01:00:00:00:00 # test
# test 2
03
03

00 
 01 
02`
	testcases := []serialNumberSetTestcase{
		{
			input:  big.NewInt(1 << 32),
			output: true,
		},
		{
			input:  big.NewInt(0),
			output: true,
		},
		{
			input:  big.NewInt(1),
			output: true,
		},
		{
			input:  big.NewInt(2),
			output: true,
		},
		{
			input:  big.NewInt(3),
			output: true,
		},
		{
			input:  big.NewInt(4),
			output: false,
		},
		{
			input:  big.NewInt(-2),
			output: true,
		},
	}
	s, err := newSerialNumberSetFromReader(strings.NewReader(testFile), nil)
	if err != nil {
		t.Fatalf("unable to load test set: %v", err)
	}
	for i, testcase := range testcases {
		t.Run(fmt.Sprintf("Testcase[%d]", i), func(t *testing.T) {
			out := s.Has(testcase.input)
			if out != testcase.output {
				t.Fatalf("expected %v, got %v", testcase.output, out)
			}
		})
	}
}

func TestSerialNumberSetEmpty(t *testing.T) {
	const testFile = ""
	testcases := []serialNumberSetTestcase{
		{
			input:  big.NewInt(0),
			output: false,
		},
		{
			input:  big.NewInt(1),
			output: false,
		},
		{
			input:  big.NewInt(2),
			output: false,
		},
	}
	s, err := newSerialNumberSetFromReader(strings.NewReader(testFile), nil)
	if err != nil {
		t.Fatalf("unable to load test set: %v", err)
	}
	for i, testcase := range testcases {
		t.Run(fmt.Sprintf("Testcase[%d]", i), func(t *testing.T) {
			out := s.Has(testcase.input)
			if out != testcase.output {
				t.Fatalf("expected %v, got %v", testcase.output, out)
			}
		})
	}
}

func TestSerialNumberSetNullMap(t *testing.T) {
	const testFile = ""
	testcases := []serialNumberSetTestcase{
		{
			input:  big.NewInt(0),
			output: false,
		},
		{
			input:  big.NewInt(1),
			output: false,
		},
		{
			input:  big.NewInt(2),
			output: false,
		},
	}
	s := new(serialNumberSet)
	for i, testcase := range testcases {
		t.Run(fmt.Sprintf("Testcase[%d]", i), func(t *testing.T) {
			out := s.Has(testcase.input)
			if out != testcase.output {
				t.Fatalf("expected %v, got %v", testcase.output, out)
			}
		})
	}
}

func TestSerialNumberSetNull(t *testing.T) {
	const testFile = ""
	testcases := []serialNumberSetTestcase{
		{
			input:  big.NewInt(0),
			output: false,
		},
		{
			input:  big.NewInt(1),
			output: false,
		},
		{
			input:  big.NewInt(2),
			output: false,
		},
	}
	s := (*serialNumberSet)(nil)
	for i, testcase := range testcases {
		t.Run(fmt.Sprintf("Testcase[%d]", i), func(t *testing.T) {
			out := s.Has(testcase.input)
			if out != testcase.output {
				t.Fatalf("expected %v, got %v", testcase.output, out)
			}
		})
	}
}
