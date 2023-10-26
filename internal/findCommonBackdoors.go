package internal

import (
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/rs/zerolog"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var commonBackdoorFiles = make([]string, 10)

func CheckCommonBackdoors(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info().Msg("Checking Common Backdoor Locations...")
	getBackdoorFiles(logger)
	for _, v := range commonBackdoorFiles {
		if v == "" {
			continue
		}
		fileStat, err := os.Stat(v)
		fileModificationTime := "NA"
		if err != nil {
			logger.Error().Err(err)
		} else {
			fileModificationTime = fileStat.ModTime().UTC().String()
		}

		tmp_ := map[string]interface{}{
			"File":         strings.TrimSpace(v),
			"LastModified": fileModificationTime,
		}
		detection := Detection{
			Name:      "",
			Severity:  0,
			Tip:       "Verify validity of script file.",
			Technique: "T1543.002",
			Metadata:  tmp_,
		}
		fileSlice := helpers.ReadFileToSlice(v, logger)
		result := false
	lineCheck:
		for _, line := range fileSlice {
			result = checkLineBackdoor(logger, detection, detections, line)
			if result {
				break lineCheck
			}
		}
		if result == false && fileModificationTime != "NA" {
			// No detection yet on this file - check for recent modification
			dayDiff := int(timestampNow.Sub(fileStat.ModTime().UTC()).Hours() / 24)
			if dayDiff <= 30 {
				// File modified within last 30 days
				detection.Name = "Script File modified within last 30 days."
				detection.Metadata["DaysAgo"] = dayDiff
				detection.Severity = 1
				detections <- detection
			}
		}

	}
}

func checkLineBackdoor(logger zerolog.Logger, detection Detection, detections chan<- Detection, lineContent string) bool {
	detection.Metadata["Line"] = lineContent
	for _, pattern := range suspiciousPatterns {
		if helpers.SearchStringContains(lineContent, pattern) {
			detection.Name = "Suspicious Pattern in Script"
			detection.Metadata["Pattern"] = pattern
			detections <- detection
			return true
		}
	}
	ipv4Match, _ := regexp.MatchString(ipv4Regex+`|`+ipv6Regex, lineContent)
	if ipv4Match {
		detection.Name = "IP Address Pattern in Script"
		detections <- detection
		return true
	}
	domainMatch, _ := regexp.MatchString(domainRegex, lineContent)
	if domainMatch {
		detection.Name = "Domain Pattern in Script"
		detections <- detection
		return true
	}
	return false
}

func getBackdoorFiles(logger zerolog.Logger) {
	backdoorDirs := []string{
		"/etc/update-motd.d",
		"/var/run/motd",
		"/etc/init.d",
		"/etc/rc.d",
		"/sbin/init.d",
		"/etc/rc.local",
		"/etc/apt/apt.conf.d",
	}
	f1, err := filepath.Glob("/home/*/.gitconfig")
	if err != nil {
		logger.Error().Err(err)
	} else {
		backdoorDirs = append(backdoorDirs, f1...)
	}

	for _, path := range backdoorDirs {
		filepath.WalkDir(path, walkf)
	}
}

func walkf(s string, d fs.DirEntry, err error) error {
	if err != nil {
		return err
	}
	if !d.IsDir() {
		commonBackdoorFiles = append(commonBackdoorFiles, s)
	}
	return nil
}
