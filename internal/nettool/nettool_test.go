package nettool

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		spec string
		want []int
	}{
		{"80", []int{80}},
		{"22,80,443", []int{22, 80, 443}},
		{"8000-8003", []int{8000, 8001, 8002, 8003}},
		{"443,80,80,22", []int{22, 80, 443}}, // dedup + sort
		{"25-22", []int{22, 23, 24, 25}},     // reversed range
		{" 80 , 443 ", []int{80, 443}},       // whitespace
	}
	for _, c := range cases {
		got, err := parsePorts(c.spec)
		if err != nil {
			t.Errorf("parsePorts(%q): unexpected error %v", c.spec, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parsePorts(%q)=%v want %v", c.spec, got, c.want)
		}
	}
}

func TestParsePortsErrors(t *testing.T) {
	for _, spec := range []string{"abc", "70000", "0", "10-x"} {
		if _, err := parsePorts(spec); err == nil {
			t.Errorf("parsePorts(%q): expected error, got nil", spec)
		}
	}
}
