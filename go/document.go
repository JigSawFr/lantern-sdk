// SPDX-License-Identifier: MIT

package lantern

import (
	"encoding/json"
	"reflect"
)

// SchemaOf is a document's schema: an integer, 1 or more (SPEC.md § 3.2); a *DocumentError otherwise.
// document is what LoadJSON gives.
func SchemaOf(document any, where string) (int64, error) {
	object, ok := document.(map[string]any)
	if !ok {
		return 0, &DocumentError{Where: where, Reason: "not an object"}
	}
	n, ok := object["schema"].(json.Number)
	if ok {
		if v, err := n.Int64(); err == nil && v >= 1 && !containsAny(string(n), ".eE") {
			return v, nil
		}
	}
	return 0, &DocumentError{Where: where, Reason: "no integer schema"}
}

func containsAny(s, chars string) bool {
	for _, c := range s {
		for _, d := range chars {
			if c == d {
				return true
			}
		}
	}
	return false
}

// Parse reads a JSON document's bytes as a T by the schema rule (SPEC.md § 3.2), within SPEC.md
// § 13's limits: a document of a newer schema than this library knows is absent, not an error,
// and is never written back. It gives a *NewerSchemaError then (errors.Is(err, ErrNewerSchema)),
// and a *DocumentError when the bytes are not a T. The fields T does not know are kept in its
// Extra, so that a document written back loses none of them.
//
//	h, err := lantern.Parse[lantern.Handshake](raw)
func Parse[T any, P interface {
	*T
	json.Unmarshaler
}](raw []byte) (*T, error) {
	name := reflect.TypeFor[T]().Name()
	value, err := LoadJSON(raw, LoadOptions{Where: name})
	if err != nil {
		return nil, err
	}
	schema, err := SchemaOf(value, name)
	if err != nil {
		return nil, err
	}
	if schema > Schema {
		return nil, &NewerSchemaError{What: name, Schema: schema}
	}
	out := new(T)
	if err := P(out).UnmarshalJSON(raw); err != nil {
		return nil, err
	}
	return out, nil
}
