package internal

import (
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
	"regexp"
)

func CheckShellConfigs(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info().Msg("Checking .bashrc Files...")
	files, err := filepath.Glob("/home/*/.bashrc")
	if err != nil {
		logger.Error().Err(err)
		return
	}
	zfiles, zerr := filepath.Glob("/home/*/.zshrc")
	if zerr != nil {
		logger.Error().Err(zerr)
		return
	}
	files = append(files, zfiles...)
	files = append(files, "/root/.bashrc")
	files = append(files, "/etc/bash.bashrc")
	files = append(files, "/etc/zsh/zshrc")
	for _, file := range files {
		if helpers.FileExists(file) == false {
			continue
		}
		fileContents := helpers.ReadFileToString(file, logger)
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
			Name:      "Suspicious Shell Configuration File",
			Severity:  2,
			Tip:       "Investigate file to determine validity.",
			Technique: "T1546.004",
			Metadata:  tmp_,
		}
	patternMatch:
		for _, pattern := range suspiciousPatterns {
			if helpers.SearchStringContains(fileContents, pattern) {
				detection.Name = "Suspicious Pattern in Shell Configuration File"
				detection.Metadata["Pattern"] = pattern
				detections <- detection
				break patternMatch
			}
		}
		ipv4Match, _ := regexp.MatchString(ipv4Regex+`|`+ipv6Regex, fileContents)
		if ipv4Match {
			detection.Name = "IP Address Pattern in Shell Configuration File"
			detections <- detection
			continue
		}
		domainMatch, _ := regexp.MatchString(domainRegex, fileContents)
		if domainMatch {
			detection.Name = "Domain Pattern in Shell Configuration File"
			detections <- detection
			continue
		}
		if fileModificationTime != "NA" {
			dayDiff := int(timestampNow.Sub(fileStat.ModTime().UTC()).Hours() / 24)
			if dayDiff <= 30 {
				// File modified within last 30 days
				detection.Name = "Shell Config modified within last 30 days."
				detection.Metadata["DaysAgo"] = dayDiff
				detections <- detection
			}
		}
	}
}
