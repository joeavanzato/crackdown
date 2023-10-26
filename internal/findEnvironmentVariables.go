package internal

import (
	"github.com/rs/zerolog"
	"os"
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

		detection.Name = "Suspicious Pattern in Environment Variable"
		result := checkSuspiciousContent(detection, detections, envValue)
		if result {
			continue
		}
		detection.Name = "IP Address Pattern in Environment Variable"
		result = checkIPContent(detection, detections, envValue)
		if result {
			continue
		}
		detection.Name = "Domain Pattern in Environment Variable"
		result = checkDomainContent(detection, detections, envValue)
		if result {
			continue
		}

	}
}
