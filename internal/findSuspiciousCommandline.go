package internal

import (
	"errors"
	"fmt"
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/mitchellh/go-ps"
	"github.com/rs/zerolog"
	"os"
	"os/exec"
	"strconv"
	"strings"
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
	// TODO - Check for IP Address in commandline

	for x := range processList {
		var process ps.Process
		process = processList[x]
		cmdlineLocation := fmt.Sprintf("/proc/%d/cmdline", process.Pid())
		cmdline := helpers.ReadFileToString(cmdlineLocation, logger)
		fullCommandLine := fmt.Sprintf("%s %s", process.Executable(), cmdline)
		lastModified := "NA"
		fileExists := true
		exePath, err2 := GetExePathFromPID(process.Pid())
		var fileStat os.FileInfo
		if err2 == nil {
			if fileStat, err = os.Stat(exePath); err == nil {
				lastModified = fileStat.ModTime().UTC().String()
			} else if errors.Is(err, os.ErrNotExist) {
				fileExists = false
			} else {
			}
		}

		tmp_ := map[string]interface{}{
			"Commandline":     fullCommandLine,
			"PID":             strconv.Itoa(process.Pid()),
			"ExeLastModified": lastModified,
			"ExePath":         exePath,
		}
		detection := Detection{
			Name:      "Suspicious Commandline",
			Severity:  2,
			Tip:       "Investigate process to determine validity.",
			Technique: "T1059",
			Metadata:  tmp_,
		}
		if fileExists == false && !strings.HasSuffix(process.Executable(), "kworker/") {
			detection.Name = "Running Process with Non-Existent File"
			detection.Severity = 3
			detections <- detection
		}
		if fileExists == true && lastModified != "NA" {
			dayDiff := int(timestampNow.Sub(fileStat.ModTime().UTC()).Hours() / 24)
			if dayDiff <= 30 {
				detection.Name = "Running Binary Modified within Last 30 Days"
				detection.Metadata["DaysAgo"] = dayDiff
				detection.Severity = 2
				detections <- detection
			}
		}

		result := false
		detection.Name = "Suspicious Pattern in Commandline"
		result = checkSuspiciousContent(detection, detections, fullCommandLine)
		if result {
			continue
		}
		detection.Name = "IP Address Pattern in Commandline"
		result = checkIPContent(detection, detections, fullCommandLine)
		if result {
			continue
		}
		detection.Name = "Domain Pattern in Commandline"
		result = checkDomainContent(detection, detections, fullCommandLine)
		if result {
			continue
		}

		//logger.Printf("PID: %d, CMDLINE: %s", process.Pid(), fullCommandLine)
	}
	return
}

func GetExePathFromPID(pid int) (string, error) {
	command := fmt.Sprintf("ls -al /proc/%v/exe", pid)
	cmd := exec.Command(command)
	stdout, err := cmd.Output()
	if err != nil {
		return "", err
	}
	exePath := strings.SplitN(string(stdout), "exe ->", 2)[1]
	return exePath, nil
}
