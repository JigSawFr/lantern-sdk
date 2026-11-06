// SPDX-License-Identifier: MIT

package schema

import (
	"regexp"
	"strings"
	"sync"
)

// matcher is a JSON Schema pattern. The schemas use Perl-style negative lookaheads at the start of
// three path patterns, which RE2 does not have; they are split into the lookaheads (each must not
// match at the start) and the rest.
type pattern struct {
	forbidden []*regexp.Regexp
	rest      *regexp.Regexp
}

var (
	patterns  sync.Map
	unicodeEs = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
)

func matcher(text string) *pattern {
	if p, ok := patterns.Load(text); ok {
		return p.(*pattern)
	}
	p := compile(text)
	patterns.Store(text, p)
	return p
}

func compile(text string) *pattern {
	re := func(s string) *regexp.Regexp {
		return regexp.MustCompile(unicodeEs.ReplaceAllString(s, `\x{$1}`))
	}
	p := &pattern{}
	rest := text
	if strings.HasPrefix(rest, "^(?!") {
		rest = rest[1:]
		for strings.HasPrefix(rest, "(?!") {
			depth, end := 0, -1
			for i := 0; i < len(rest) && end < 0; i++ {
				switch rest[i] {
				case '\\':
					i++
				case '(':
					depth++
				case ')':
					depth--
					if depth == 0 {
						end = i
					}
				}
			}
			if end < 0 {
				panic("schema: unbalanced lookahead in " + text)
			}
			p.forbidden = append(p.forbidden, re("^(?:"+rest[3:end]+")"))
			rest = rest[end+1:]
		}
		rest = "^" + rest
	}
	p.rest = re(rest)
	return p
}

func (p *pattern) match(s string) bool {
	for _, f := range p.forbidden {
		if f.MatchString(s) {
			return false
		}
	}
	return p.rest.MatchString(s)
}
