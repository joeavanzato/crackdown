package internal

import (
	"fmt"
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/rs/zerolog"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
)

type Detection struct {
	Name      string
	Severity  int
	Tip       string
	Technique string
	Metadata  map[string]interface{}
}

func (d Detection) MarshalZerologObject(e *zerolog.Event) {
	e.Str("name", d.Name).
		Int("severity", d.Severity).
		Str("tip", d.Tip).
		Str("technique", d.Technique).
		Fields(d.Metadata)
}

func (d Detection) MetaToPairs() string {
	if len(d.Metadata) != 0 {
		baseString := ""
		for k, v := range d.Metadata {
			baseString += fmt.Sprintf("%s: %v ||| ", k, v)
		}
		return baseString
	} else {
		return ""
	}
}

func (d Detection) String() string {
	// Format the string of a detection to properly iterate over the Metadata when rendering
	// TODO - Ths second loop after sort for some reason is introducing empty keys to the array - not sure why.
	// - I think the above is because we are not trimming /n - now we are doing this properly in each string read from files.
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

func checkDomainContent(detection Detection, detections chan<- Detection, lineContent string) bool {
	domainMatch, _ := regexp.MatchString(domainRegex, lineContent)
	if domainMatch {
		detections <- detection
		return true
	}
	return false
}

func checkSuspiciousContent(detection Detection, detections chan<- Detection, lineContent string) bool {
	for _, pattern := range suspiciousPatterns {
		if helpers.SearchStringContains(lineContent, pattern) {
			detection.Metadata["Pattern"] = pattern
			detections <- detection
			return true
		}
	}
	return false
}

func checkWebshellContent(detection Detection, detections chan<- Detection, lineContent string) bool {
	for _, pattern := range webshellIndicatorStrings {
		if helpers.SearchStringContains(lineContent, pattern) {
			detection.Metadata["Pattern"] = pattern
			detections <- detection
			return true
		}
	}
	return false
}

func checkIPContent(detection Detection, detections chan<- Detection, lineContent string) bool {
	ipv4Match, _ := regexp.MatchString(ipv4Regex+`|`+ipv6Regex, lineContent)
	if ipv4Match {
		detections <- detection
		return true
	}
	return false
}

type WaitGroupCount struct {
	sync.WaitGroup
	count int64
}

func (wg *WaitGroupCount) Add(delta int) {
	atomic.AddInt64(&wg.count, int64(delta))
	wg.WaitGroup.Add(delta)
}

func (wg *WaitGroupCount) Done() {
	atomic.AddInt64(&wg.count, -1)
	wg.WaitGroup.Done()
}

func (wg *WaitGroupCount) GetCount() int {
	return int(atomic.LoadInt64(&wg.count))
}

var filesScannedGlobal = make([]string, 10)

func CheckFileIsScanned(filename string) bool {
	if helpers.SliceContains(filesScannedGlobal, filename) {
		return true
	} else {
		filesScannedGlobal = append(filesScannedGlobal, filename)
		return false
	}
}
