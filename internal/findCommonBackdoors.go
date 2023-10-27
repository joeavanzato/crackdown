package internal

import (
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/rs/zerolog"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var commonBackdoorFiles = make([]string, 10)

func CheckCommonBackdoors(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info().Msg("Checking Common Backdoor Locations...")
	getBackdoorFiles(logger)
	for _, file := range commonBackdoorFiles {
		if file == "" {
			continue
		}
		if CheckFileIsScanned(file) {
			continue
		}
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
			Tip:       "Verify validity of script file.",
			Technique: "T1543.002",
			Metadata:  tmp_,
		}
		fileSlice := helpers.ReadFileToSlice(file, logger)
		result := false
	lineCheck:
		for _, line := range fileSlice {
			detection.Metadata["Line"] = line
			detection.Name = "Webshell Pattern in Script File"
			result = checkWebshellContent(detection, detections, line)
			if result {
				break lineCheck
			}
			detection.Name = "Suspicious Pattern in Script File"
			result = checkSuspiciousContent(detection, detections, line)
			if result {
				break lineCheck
			}
			detection.Name = "IP Address Pattern in Script File"
			result = checkIPContent(detection, detections, line)
			if result {
				break lineCheck
			}
			detection.Name = "Domain Pattern in Script File"
			result = checkDomainContent(detection, detections, line)
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

func getBackdoorFiles(logger zerolog.Logger) {
	backdoorDirs := []string{
		"/etc/update-motd.d",
		"/var/run/motd",
		"/etc/init.d",
		"/etc/rc.d",
		"/sbin/init.d",
		"/etc/rc.local",
		"/etc/apt/apt.conf.d",
		"/usr/share/unattended-upgrades",
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
	commonBackdoorFiles = append(commonBackdoorFiles, "/etc/at.allow")
	commonBackdoorFiles = append(commonBackdoorFiles, "/etc/at.deny")
	commonBackdoorFiles = append(commonBackdoorFiles, "/etc/doas.conf")
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
