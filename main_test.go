package main

import "testing"

// TestIsPassthroughCommand mirrors the passthrough rules from src/passthrough.ts.
func TestIsPassthroughCommand(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, true},                                 // no args = help
		{[]string{"login"}, true},                   //
		{[]string{"logout"}, true},                  //
		{[]string{"lock"}, true},                    //
		{[]string{"config"}, true},                  //
		{[]string{"update"}, true},                  //
		{[]string{"completion"}, true},              //
		{[]string{"status"}, true},                  //
		{[]string{"serve"}, true},                   //
		{[]string{"--help"}, true},                  //
		{[]string{"-h"}, true},                      //
		{[]string{"--version"}, true},               //
		{[]string{"-v"}, true},                      //
		{[]string{"list", "items", "--help"}, true}, // flags anywhere
		{[]string{"get", "item", "--version"}, true},
		{[]string{"unlock"}, false},
		{[]string{"list", "items"}, false},
		{[]string{"get", "password", "name"}, false},
		{[]string{"generate"}, false},
	}
	for _, c := range cases {
		if got := isPassthroughCommand(c.args); got != c.want {
			t.Errorf("isPassthroughCommand(%q) = %v, want %v", c.args, got, c.want)
		}
	}
}
