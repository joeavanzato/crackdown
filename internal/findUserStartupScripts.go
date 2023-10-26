package internal

import (
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
	"regexp"
)

func CheckUserStartupScripts(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info().Msg("Checking User Startup Files...")
	files, err := filepath.Glob("/home/*/.*")
	if err != nil {
		logger.Error().Err(err)
		return
	}
	rootFiles, err2 := filepath.Glob("/root/.*")
	if err2 != nil {
		logger.Error().Err(err2)
		return
	}
	files = append(files, rootFiles...)
	for _, file := range files {
		if helpers.FileExists(file) == false {
			continue
		}

		// File Modification Check
		fileStat, err := os.Stat(file)
		fileModificationTime := "NA"
		if err != nil {
			logger.Error().Err(err)
		} else {
			fileModificationTime = fileStat.ModTime().UTC().String()
		}
		tmp_ := map[string]interface{}{
			"Modified": fileModificationTime,
			"File":     file,
		}
		detection := Detection{
			Name:      "Suspicious User Startup Script",
			Severity:  0,
			Tip:       "Investigate file to determine validity.",
			Technique: "T1546",
			Metadata:  tmp_,
		}
		fileSlice := helpers.ReadFileToSlice(file, logger)
		result := false
	lineCheck:
		for _, line := range fileSlice {
			result = checkScriptLine(logger, detection, detections, line)
			if result {
				break lineCheck
			}

		}
		if result == false && fileModificationTime != "NA" {
			dayDiff := int(timestampNow.Sub(fileStat.ModTime().UTC()).Hours() / 24)
			if dayDiff <= 30 {
				// File modified within last 30 days
				detection.Severity = 1
				detection.Name = "User Startup Script modified within last 30 days."
				detection.Metadata["DaysAgo"] = dayDiff
				detections <- detection
			}
		}
	}
}

func checkScriptLine(logger zerolog.Logger, detection Detection, detections chan<- Detection, lineContent string) bool {
	detection.Metadata["Line"] = lineContent
	for _, pattern := range suspiciousPatterns {
		if helpers.SearchStringContains(lineContent, pattern) {
			detection.Severity = 3
			detection.Name = "Suspicious Pattern in User Startup Script"
			detection.Metadata["Pattern"] = pattern
			detections <- detection
			return true
		}
	}
	ipv4Match, _ := regexp.MatchString(ipv4Regex+`|`+ipv6Regex, lineContent)
	if ipv4Match {
		detection.Severity = 2
		detection.Name = "IP Address Pattern in User Startup Script"
		detections <- detection
		return true
	}
	domainMatch, _ := regexp.MatchString(domainRegex, lineContent)
	if domainMatch {
		detection.Severity = 2
		detection.Name = "Domain Pattern in User Startup Script"
		detections <- detection
		return true
	}
	return false
}
