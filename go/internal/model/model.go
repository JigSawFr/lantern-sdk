// SPDX-License-Identifier: MIT

// Package model is the codec the generated documents are made of: it reads a
// JSON object into a struct and writes it back, keeping the fields the struct
// does not know in its Extra field, so that a document read and written back
// loses nothing (SPEC.md § 3.2).
//
// A field is described by its struct tag: `json:"key"` names it, and the
// optional `lantern:"required,nullable"` says that the key must be present
// (and not null) and that null is a value it may hold.
package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
)

type field struct {
	index    int
	key      string
	required bool
	nullable bool
}

type shape struct {
	fields []field
	known  map[string]bool
	extra  int // index of Extra, or -1
	nulls  int // index of Nulls, or -1
}

var (
	extraType = reflect.TypeOf(map[string]json.RawMessage(nil))
	nullsType = reflect.TypeOf(map[string]bool(nil))
	shapes    sync.Map // reflect.Type -> *shape
)

func shapeOf(t reflect.Type) *shape {
	if s, ok := shapes.Load(t); ok {
		return s.(*shape)
	}
	s := &shape{known: map[string]bool{}, extra: -1, nulls: -1}
	for i := range t.NumField() {
		f := t.Field(i)
		switch {
		case f.Name == "Extra" && f.Type == extraType:
			s.extra = i
			continue
		case f.Name == "Nulls" && f.Type == nullsType:
			s.nulls = i
			continue
		}
		key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if key == "" || key == "-" {
			continue
		}
		fl := field{index: i, key: key}
		for _, flag := range strings.Split(f.Tag.Get("lantern"), ",") {
			switch flag {
			case "required":
				fl.required = true
			case "nullable":
				fl.nullable = true
			}
		}
		s.fields = append(s.fields, fl)
		s.known[key] = true
	}
	shapes.Store(t, s)
	return s
}

// Error is a document that cannot be read: Where says which field, as a path.
type Error struct {
	Where  string
	Reason string
}

func (e *Error) Error() string {
	if e.Where == "" {
		return e.Reason
	}
	return e.Where + ": " + e.Reason
}

// Decode reads a JSON object into the struct v points to.
func Decode(data []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("model: %T is not a pointer to a struct", v)
	}
	rv = rv.Elem()
	name := rv.Type().Name()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return &Error{Where: name, Reason: "not an object"}
	}
	s := shapeOf(rv.Type())
	rv.SetZero()
	for _, f := range s.fields {
		raw, present := object[f.key]
		isNull := present && bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
		switch {
		case !present:
			if f.required {
				return &Error{Where: name, Reason: "no " + f.key}
			}
			continue
		case isNull && f.required && !f.nullable:
			return &Error{Where: name + "." + f.key, Reason: "is null"}
		case isNull:
			if !f.required && f.nullable && s.nulls >= 0 {
				nulls := rv.Field(s.nulls)
				if nulls.IsNil() {
					nulls.Set(reflect.MakeMap(nullsType))
				}
				nulls.SetMapIndex(reflect.ValueOf(f.key), reflect.ValueOf(true))
			}
			continue // a null is absent for an optional field, nil for a nullable one
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(rv.Field(f.index).Addr().Interface()); err != nil {
			return &Error{Where: name + "." + f.key, Reason: reason(err)}
		}
	}
	if s.extra >= 0 {
		for key, raw := range object {
			if s.known[key] {
				continue
			}
			extra := rv.Field(s.extra)
			if extra.IsNil() {
				extra.Set(reflect.MakeMap(extraType))
			}
			extra.SetMapIndex(reflect.ValueOf(key), reflect.ValueOf(append(json.RawMessage(nil), raw...)))
		}
	}
	return nil
}

func reason(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Where + ": " + e.Reason
	}
	if e, ok := err.(*json.UnmarshalTypeError); ok {
		return "not " + e.Type.String() + " (" + e.Value + ")"
	}
	return err.Error()
}

// Encode writes the struct v (or a pointer to it) as a JSON object: its fields
// in their order, then the fields it did not know, sorted.
func Encode(v any) ([]byte, error) {
	rv := reflect.Indirect(reflect.ValueOf(v))
	s := shapeOf(rv.Type())
	var out bytes.Buffer
	out.WriteByte('{')
	first := true
	put := func(key string, value []byte) {
		if !first {
			out.WriteByte(',')
		}
		first = false
		k, _ := json.Marshal(key)
		out.Write(k)
		out.WriteByte(':')
		out.Write(value)
	}
	for _, f := range s.fields {
		fv := rv.Field(f.index)
		absent := false
		switch fv.Kind() {
		case reflect.Pointer, reflect.Interface:
			absent = fv.IsNil()
		case reflect.Slice, reflect.Map:
			absent = fv.IsNil() && !f.required
		}
		if absent && !f.required {
			if f.nullable && s.nulls >= 0 && rv.Field(s.nulls).MapIndex(reflect.ValueOf(f.key)).IsValid() {
				put(f.key, []byte("null"))
			}
			continue
		}
		var raw []byte
		var err error
		switch {
		case fv.Kind() == reflect.Slice && fv.IsNil():
			raw = []byte("[]")
		case fv.Kind() == reflect.Map && fv.IsNil():
			raw = []byte("{}")
		default:
			raw, err = marshal(fv.Interface())
		}
		if err != nil {
			return nil, err
		}
		put(f.key, raw)
	}
	if s.extra >= 0 {
		extra := rv.Field(s.extra).Interface().(map[string]json.RawMessage)
		keys := make([]string, 0, len(extra))
		for k := range extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			put(k, extra[k])
		}
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
