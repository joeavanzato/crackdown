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

var serviceFilePaths = make([]string, 10)

func CheckStartupServices(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info().Msg("Finding System Services...")
	err := getServiceFiles(logger)
	if err != nil {
		logger.Error().Err(err)
		return
	}
	for _, file := range serviceFilePaths {
		fileStat, err := os.Stat(file)
		fileModificationTime := "NA"
		if err != nil {
			logger.Error().Err(err)
		} else {
			fileModificationTime = fileStat.ModTime().UTC().String()
		}

		tmp_ := map[string]interface{}{
			"File":         strings.TrimSpace(file),
			"LastModified": fileModificationTime,
		}
		detection := Detection{
			Name:      "",
			Severity:  0,
			Tip:       "Verify validity of installed service/configuration file.",
			Technique: "T1543.002",
			Metadata:  tmp_,
		}
		fileSlice := helpers.ReadFileToSlice(file, logger)
		result := false
	lineCheck:
		for _, line := range fileSlice {
			if strings.HasPrefix(line, "Exec") || strings.HasPrefix(line, "Environment=") {
				result = checkLine(logger, detection, detections, line)
				if result {
					break lineCheck
				}
			}
		}
		if result == false && fileModificationTime != "NA" {
			// No detection yet on this file - check for recent modification
			dayDiff := int(timestampNow.Sub(fileStat.ModTime().UTC()).Hours() / 24)
			if dayDiff <= 30 {
				// File modified within last 30 days
				detection.Name = "Service File modified within last 30 days."
				detection.Metadata["DaysAgo"] = dayDiff
				detection.Severity = 1
				detections <- detection
			}
		}
	}
}

func checkLine(logger zerolog.Logger, detection Detection, detections chan<- Detection, lineContent string) bool {
	lineData := strings.SplitN(lineContent, "=", 2)
	detection.Metadata[lineData[0]] = lineContent
	detection.Metadata["ConfigType"] = lineData[0]
	for _, pattern := range suspiciousPatterns {
		if helpers.SearchStringContains(lineData[1], pattern) {
			detection.Name = "Suspicious Pattern in Service ExecStart"
			detection.Metadata["Pattern"] = pattern
			detections <- detection
			return true
		}
	}
	ipv4Match, _ := regexp.MatchString(ipv4Regex+`|`+ipv6Regex, lineContent)
	if ipv4Match {
		detection.Name = "IP Address Pattern in Service Configuration"
		detections <- detection
		return true
	}
	domainMatch, _ := regexp.MatchString(domainRegex, lineContent)
	if domainMatch {
		detection.Name = "Domain Pattern in Service Configuration"
		detections <- detection
		return true
	}
	return false
}

func getServiceFiles(logger zerolog.Logger) error {
	serviceDirs := []string{"/etc/systemd/system", "/run/systemd/system", "/lib/systemd/system"}
	for _, path := range serviceDirs {
		filepath.WalkDir(path, walk)
	}
	return nil
}

func walk(s string, d fs.DirEntry, err error) error {
	if err != nil {
		return err
	}
	if !d.IsDir() && (strings.HasSuffix(s, ".conf") || strings.HasSuffix(s, ".service")) {
		serviceFilePaths = append(serviceFilePaths, s)
	}
	return nil
}
