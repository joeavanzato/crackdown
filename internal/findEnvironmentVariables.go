package internal

import (
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/rs/zerolog"
	"os"
	"regexp"
	"strings"
)

func CheckEnvironmentVariables(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info().Msg("Checking Environment Variables...")
	envs := os.Environ()
	for _, v := range envs {
		envSplit := strings.SplitN(v, "=", 2)
		envKey := envSplit[0]
		envValue := envSplit[1]
		tmp_ := map[string]interface{}{
			"EnvKey":   envKey,
			"EnvValue": envValue,
		}
		detection := Detection{
			Name:      "Suspicious Environment Variable",
			Severity:  3,
			Tip:       "Investigate the variable to determine validity.",
			Technique: "T1574",
			Metadata:  tmp_,
		}
		checkContent(detection, detections, envValue)

	}
}

func checkContent(detection Detection, detections chan<- Detection, lineContent string) bool {
	for _, pattern := range suspiciousPatterns {
		if helpers.SearchStringContains(lineContent, pattern) {
			detection.Name = "Suspicious Pattern in Environment Variable"
			detection.Metadata["Pattern"] = pattern
			detections <- detection
			return true
		}
	}
	ipv4Match, _ := regexp.MatchString(ipv4Regex+`|`+ipv6Regex, lineContent)
	if ipv4Match {
		detection.Name = "IP Address Pattern in Environment Variable"
		detections <- detection
		return true
	}
	domainMatch, _ := regexp.MatchString(domainRegex, lineContent)
	if domainMatch {
		detection.Name = "Domain Pattern in Environment Variable"
		detections <- detection
		return true
	}
	return false
}
