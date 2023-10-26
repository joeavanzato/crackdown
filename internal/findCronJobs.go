package internal

import (
	"fmt"
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/rs/zerolog"
	"os"
	"regexp"
	"strings"
)

func FindCronJobs(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info().Msg("Finding Cron Jobs...")
	cronDirs := []string{"/var/spool/cron/crontabs", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly", "/etc/cron.d"}
	cronFilePaths := make([]string, 10)
	for _, path := range cronDirs {
		files, err := os.ReadDir(path)
		if err != nil {
			logger.Error().Err(err)
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

	cronRegex := regexp.MustCompile(`[\d*]{1,4}\s[\d*]{1,4}\s[\d*]{1,4}\s[\d*]{1,4}\s[\d*]{1,4}\s(?P<user>.*?)\s.*?(?P<command>.+)`)
	for _, cronFile := range cronFilePaths {
		// TODO - IP Check in Cronjob Line
		// TODO - General Cleanup
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
				tmp_ := map[string]interface{}{
					"User":    "root",
					"Command": results["command"],
					"File":    cronFile,
				}
				detection := Detection{
					Name:      "Cronjob Review",
					Severity:  1,
					Tip:       "Verify validity of cronjob.",
					Technique: "T1053.003",
					Metadata:  tmp_,
				}

				// Suspicious String Cronjob Detection
				susPatternMatch := false
			patternMatch:
				for _, pattern := range suspiciousPatterns {
					if strings.Contains(line, pattern) {
						detection.Severity = 2
						detection.Name = "Suspicious Pattern in Cronjob Command"
						detection.Metadata["Pattern"] = pattern
						detection.Metadata["User"] = results["user"]
						detections <- detection
						susPatternMatch = true
						break patternMatch
					}
				}
				if susPatternMatch {
					continue
				}

				// IP/Domain Regex Detection
				ipv4Match, _ := regexp.MatchString(ipv4Regex+`|`+ipv6Regex, line)
				if ipv4Match {
					detection.Metadata["User"] = results["user"]
					detection.Metadata["Line"] = line
					detection.Name = "IP Address Pattern in Cron line"
					detections <- detection
					continue
				}
				domainMatch, _ := regexp.MatchString(domainRegex, line)
				if domainMatch {
					detection.Metadata["User"] = results["user"]
					detection.Metadata["Line"] = line
					detection.Name = "Domain Pattern in Cron line"
					detections <- detection
					continue
				}

				// Root Cronjob Detection - Should be last as a system-wide catch-all
				if results["user"] == "root" {
					detection.Metadata["User"] = "root"
					detection.Name = "Root Cronjob Review"
					detections <- detection
					continue
				}

				// TODO - Review - Removing generic cronjob review for now.
				/*tmp_ := map[string]interface{}{
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
				}*/
				//detections <- detection
			}
		}
	}
	return

}
