package hostpattern

import "testing"

func TestMatchCaseInsensitiveAndWildcards(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*.Example.COM", "API.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "deep.api.example.com", false},
		{"**.example.com", "deep.api.example.com", true},
		{"*-api.example.com", "tenant-api.example.com", true},
		{"*", "deep.api.example.com", false},
		{"**.example.com", "api.example.com", true},
		{"**.example.com", "example.com", false},
		{"api.**.com", "api.x.y.com", true},
		{"api.**.com", "api.com", false},
		{"**", "deep.api.example.com", true},
		{"**", "localhost", true},
		{"**", "", false},
		{"**", "api..example.com", false},
	}
	for _, tc := range cases {
		got, err := MatchString(tc.pattern, tc.host)
		if err != nil {
			t.Fatalf("MatchString(%q,%q): %v", tc.pattern, tc.host, err)
		}
		if got != tc.want {
			t.Errorf("MatchString(%q,%q)=%v want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	bad := []string{
		"",
		"api .example.com",
		"*.{prod,staging}.example.com",
		"api**.example.com",
		"api..example.com",
	}
	for _, p := range bad {
		if _, err := Parse(p); err == nil {
			t.Errorf("Parse(%q) expected error", p)
		}
	}
}
