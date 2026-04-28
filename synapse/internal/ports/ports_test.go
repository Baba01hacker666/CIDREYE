package ports

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{"single port", "80", []int{80}, false},
		{"multiple ports", "80,443", []int{80, 443}, false},
		{"port range", "1-3", []int{1, 2, 3}, false},
		{"mixed", "80, 443, 8080-8082", []int{80, 443, 8080, 8081, 8082}, false},
		{"duplicates", "80,80, 443, 443", []int{80, 443}, false},
		{"empty", "", nil, true},
		{"invalid format", "80-", nil, true},
		{"invalid char", "abc", nil, true},
		{"out of range low", "0", nil, true},
		{"out of range high", "65536", nil, true},
		{"invalid range bounds", "10-5", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}
