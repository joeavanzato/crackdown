package internal

import (
	"fmt"
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/sirupsen/logrus"
	"os"
	"regexp"
	"strings"
)

func FindCronJobs(logger *logrus.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info("Finding Cron Jobs...")
	cronDirs := []string{"/var/spool/cron/crontabs", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly", "/etc/cron.d"}
	cronFilePaths := make([]string, 10)
	for _, path := range cronDirs {
		files, err := os.ReadDir(path)
		if err != nil {
			logger.Error(err)
			continue
		}
		for _, file := range files {
			tmp_name := fmt.Sprintf("%s/%s", path, file.Name())
			cronFilePaths = append(cronFilePaths, tmp_name)
		}
	}
	// root crontab on ubuntu-like systems
	if helpers.FileExists("/etc/crontab") {
		cronFilePaths = append(cronFilePaths, "/etc/crontab")
	}

	suspiciousPatterns := []string{"https://", "/bin/sh -c", "/dev/tcp", "/dev/null", "bash -i >&", "$(dig"}
	cronRegex := regexp.MustCompile(`[\d*]{1,4}\s[\d*]{1,4}\s[\d*]{1,4}\s[\d*]{1,4}\s[\d*]{1,4}\s(?P<user>.*?)\s.*?(?P<command>.+)`)
	for _, cronFile := range cronFilePaths {
		// slice capacity grows beyond actual files that we store in it due to go adding more than is required when increasing cap
		if cronFile != "" {
			lines := helpers.ReadFileToSlice(cronFile, logger)
			for _, line := range lines {
				if strings.HasPrefix(line, "#") {
					continue
				}
				match := cronRegex.FindStringSubmatch(line)
				if match == nil {
					continue
				}

				results := map[string]string{}
				for i, name := range match {
					results[cronRegex.SubexpNames()[i]] = name
				}

				// Suspicious String Cronjob Detection
				susPatternMatch := false
			patternMatch:
				for _, pattern := range suspiciousPatterns {
					if strings.Contains(line, pattern) {
						tmp_ := map[string]string{
							"User":    results["user"],
							"Command": results["command"],
							"File":    cronFile,
							"Pattern": pattern,
						}
						detection := Detection{
							Name:      "Suspicious string in Cronjob",
							Severity:  2,
							Tip:       "Verify validity of cronjob.",
							Technique: "T1053.003",
							Metadata:  tmp_,
						}
						detections <- detection
						susPatternMatch = true
						break patternMatch
					}
				}
				if susPatternMatch {
					continue
				}
				// Root Cronjob Detection
				if results["user"] == "root" {
					tmp_ := map[string]string{
						"User":    "root",
						"Command": results["command"],
						"File":    cronFile,
					}
					detection := Detection{
						Name:      "Root Cronjob Review",
						Severity:  1,
						Tip:       "Verify validity of cronjob.",
						Technique: "T1053.003",
						Metadata:  tmp_,
					}
					detections <- detection
					continue
				}

				tmp_ := map[string]string{
					"User":    results["user"],
					"Command": results["command"],
					"File":    cronFile,
				}
				detection := Detection{
					Name:      "Cronjob Review",
					Severity:  0,
					Tip:       "Verify validity of cronjob.",
					Technique: "T1053.003",
					Metadata:  tmp_,
				}
				detections <- detection
			}
		}
	}
	return

}
