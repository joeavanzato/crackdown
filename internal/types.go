package internal

import (
	"fmt"
	"reflect"
	"sort"
)

type Detection struct {
	Name      string
	Severity  int
	Tip       string
	Technique string
	Metadata  map[string]string
}

func (d Detection) String() string {
	// Format the string of a detection to properly iterate over the Metadata when rendering
	// TODO - Ths second loop after sort for some reason is introducing empty keys to the array - not sure why.
	var base string
	dv := reflect.ValueOf(d)
	typeOfS := dv.Type()
	for i := 0; i < dv.NumField(); i++ {
		k := typeOfS.Field(i).Name
		v := dv.Field(i).Interface()
		if k == "Metadata" {
			base += "Metadata: "

			keys := make([]string, len(d.Metadata))
			for j, _ := range d.Metadata {
				if j != "" {
					keys = append(keys, j)
				}
			}
			sort.Strings(keys)

			for _, jj := range keys {
				if jj != "" {
					base += fmt.Sprintf("%s: %s, ", jj, d.Metadata[jj])
				}
			}

			/*for kk, vv := range d.Metadata {
				base += fmt.Sprintf("%s: %s, ", kk, vv)
			}*/
		} else if k == "Severity" {
			base += fmt.Sprintf("%s: %d, ", k, v)
		} else {
			base += fmt.Sprintf("%s: %s, ", k, v)
		}
	}
	return base
}
