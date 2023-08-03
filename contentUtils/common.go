package contentUtils

import (
	"reflect"
)

const (
	// Default state claim used for 3LO flow (3LO means "three-legged OAuth" or "authorization code grants")
	stateDefault = "state"
)

// from https://github.com/golang/go/issues/40247
func jsonTagOf(t interface{}, field string) string {
	rt := reflect.TypeOf(t)
	if rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct {
		// fmt.Printf("cannot get JSON field stag %s: the struct is not valid", field)
	}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.Name == field {
			return f.Tag.Get("json")
		}
	}
	// fmt.Printf("JSON field tag %s not found", field)
	return ""
}
