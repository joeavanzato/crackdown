package internal

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
