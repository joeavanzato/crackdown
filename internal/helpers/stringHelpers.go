package helpers

import (
	"golang.org/x/text/language"
	"golang.org/x/text/search"
)

func SearchStringContains(str string, substr string) bool {
	m := search.New(language.English, search.IgnoreCase)
	start, _ := m.IndexString(str, substr)
	if start == -1 {
		return false
	}
	return true
}

func SliceContains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
