package resolver

import (
	"testing"

	"github.com/coredns/caddy"
)

// TestSetup tests the various things that should be parsed by setup.
// Make sure you also test for parse errors.
func TestSetup(t *testing.T) {
	c := caddy.NewTestController("dns", `resolver`)
	if err := setup(c); err != nil {
		t.Fatalf("Expected no errors, but got: %v", err)
	}

	c = caddy.NewTestController("dns", `resolver more`)
	if err := setup(c); err == nil {
		t.Fatalf("Expected errors, but got: %v", err)
	}
}


func TestResolverParse(t *testing.T) {
	zoneFileName1, rm, err := test.TempFile(".", dbMiekNL)
	if err != nil {
		t.Fatal(err)
	}
	defer rm()

	zoneFileName2, rm, err := test.TempFile(".", dbDnssexNLSigned)
	if err != nil {
		t.Fatal(err)
	}
	defer rm()

	tests := []struct {
		name				string
		input 		        string
		shouldErr           bool
		expectedErr			string

	}{
		{
			"should work with most basic setup"
			"resolver",
			false,
		},
		{
			"should fail because of non-existent option"
			`resolver {
				no_reload
			}`,
			true,
		},
		{
			"should fail because of incorrect header"
			`repsolver`,
			true,
		},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.inputFileRules)
		actualZones, actualFallthrough, err := fileParse(c)

		if err == nil && test.shouldErr {
			t.Fatalf("Test %d expected errors, but got no error", i)
		} else if err != nil && !test.shouldErr {
			t.Fatalf("Test %d expected no errors, but got '%v'", i, err)
		} else {
			if len(actualZones.Names) != len(test.expectedZones.Names) {
				t.Fatalf("Test %d expected %v, got %v", i, test.expectedZones.Names, actualZones.Names)
			}
			for j, name := range test.expectedZones.Names {
				if actualZones.Names[j] != name {
					t.Fatalf("Test %d expected %v for %d th zone, got %v", i, name, j, actualZones.Names[j])
				}
			}
			if !actualFallthrough.Equal(test.expectedFallthrough) {
				t.Errorf("Test %d expected fallthrough of %v, got %v", i, test.expectedFallthrough, actualFallthrough)
			}
		}
	}
}