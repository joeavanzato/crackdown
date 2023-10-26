package internal

import (
	"fmt"
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/mitchellh/go-ps"
	"github.com/rs/zerolog"
	"strconv"
)

func FindSuspiciousCommandlines(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info().Msg("Finding Suspicious Processes...")
	processList, err := ps.Processes()
	if err != nil {
		logger.Error().Err(err)
		return
	}
	// https://detection.fyi/sigmahq/sigma/linux/builtin/lnx_shell_susp_rev_shells/
	// TODO - Port Forwarding
	// TODO - Suspicious Executable Locations

	for x := range processList {
		var process ps.Process
		process = processList[x]
		cmdlineLocation := fmt.Sprintf("/proc/%d/cmdline", process.Pid())
		cmdline := helpers.ReadFileToString(cmdlineLocation, logger)
		fullCommandLine := fmt.Sprintf("%s %s", process.Executable(), cmdline)
	patternMatch:
		for _, pattern := range suspiciousPatterns {
			//logger.Info(pattern)
			if helpers.SearchStringContains(fullCommandLine, pattern) {
				tmp_ := map[string]interface{}{
					"Commandline": fullCommandLine,
					"Pattern":     pattern,
					"PID":         strconv.Itoa(process.Pid()),
				}
				detection := Detection{
					Name:      "Suspicious Commandline",
					Severity:  2,
					Tip:       "Investigate process to determine validity.",
					Technique: "T1059",
					Metadata:  tmp_,
				}
				detections <- detection
				break patternMatch
			}
		}
		//logger.Printf("PID: %d, CMDLINE: %s", process.Pid(), fullCommandLine)
	}
	return
}
