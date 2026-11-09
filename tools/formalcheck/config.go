package main

import (
	"regexp"
	"strings"
)

// TLC property declarations may span lines. Tokenize comments and quoted
// constants separately so neither can accidentally start or end a declaration.
var configToken = regexp.MustCompile(`(?s)\(\*.*?\*\)|\\\*[^\r\n]*|"(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z_0-9]*|\S`)

type propertyDeclaration struct {
	start, end int
	names      []string
}

func configKeyword(s string) bool {
	switch s {
	case "CONSTANT", "CONSTANTS", "CONSTRAINT", "CONSTRAINTS", "ACTION_CONSTRAINT", "ACTION_CONSTRAINTS",
		"INIT", "NEXT", "SPECIFICATION", "VIEW", "SYMMETRY", "INVARIANT", "INVARIANTS", "PROPERTY", "PROPERTIES",
		"CHECK_DEADLOCK", "ALIAS", "POSTCONDITION", "PERIODIC", "_PERIODIC", "RL_REWARD":
		return true
	}
	return false
}

func propertyDeclarations(cfg string) []propertyDeclaration {
	var tokens [][2]int
	for _, at := range configToken.FindAllStringIndex(cfg, -1) {
		s := cfg[at[0]:at[1]]
		if !strings.HasPrefix(s, `\*`) && !strings.HasPrefix(s, "(*") {
			tokens = append(tokens, [2]int{at[0], at[1]})
		}
	}
	var out []propertyDeclaration
	for i := 0; i < len(tokens); i++ {
		s := cfg[tokens[i][0]:tokens[i][1]]
		if s != "INVARIANT" && s != "INVARIANTS" && s != "PROPERTY" && s != "PROPERTIES" {
			continue
		}
		d := propertyDeclaration{start: tokens[i][0], end: len(cfg)}
		for i++; i < len(tokens); i++ {
			s = cfg[tokens[i][0]:tokens[i][1]]
			if configKeyword(s) {
				d.end = tokens[i][0]
				i--
				break
			}
			d.names = append(d.names, s)
		}
		out = append(out, d)
	}
	return out
}

func withoutProperties(cfg string) string {
	var b strings.Builder
	end := 0
	for _, d := range propertyDeclarations(cfg) {
		b.WriteString(cfg[end:d.start])
		end = d.end
	}
	b.WriteString(cfg[end:])
	return b.String()
}
