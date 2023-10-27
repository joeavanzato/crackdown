package internal

import (
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/rs/zerolog"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var serviceFilePaths = make([]string, 10)

func CheckStartupServices(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	// https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html
	// ^ Good description of linux service confs
	defer waitGroup.Done()
	logger.Info().Msg("Finding System Services...")
	err := getServiceFiles(logger)
	if err != nil {
		logger.Error().Err(err)
		return
	}
	for _, file := range serviceFilePaths {

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
			Tip:       "Verify validity of installed service/configuration file.",
			Technique: "T1543.002",
			Metadata:  tmp_,
		}
		fileSlice := helpers.ReadFileToSlice(file, logger)
		result := false
	lineCheck:
		for _, line := range fileSlice {
			if strings.HasPrefix(line, "Exec") || strings.HasPrefix(line, "Environment") {
				lineData := strings.SplitN(line, "=", 2)
				detection.Metadata[lineData[0]] = line
				detection.Metadata["ConfigType"] = lineData[0]
				detection.Metadata["Line"] = line

				detection.Name = "Webshell Pattern in Service Configuration"
				result = checkWebshellContent(detection, detections, lineData[1])
				if result {
					break lineCheck
				}
				detection.Name = "Suspicious Pattern in Service Configuration"
				result = checkSuspiciousContent(detection, detections, lineData[1])
				if result {
					break lineCheck
				}
				detection.Name = "IP Address Pattern in Service Configuration"
				result = checkIPContent(detection, detections, lineData[1])
				if result {
					break lineCheck
				}
				detection.Name = "Domain Pattern in Service Configuration"
				result = checkDomainContent(detection, detections, lineData[1])
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
				detection.Severity = 2
				detections <- detection
			}
		}
	}
}

func getServiceFiles(logger zerolog.Logger) error {
	serviceDirs := []string{"/etc/systemd/system", "/etc/systemd/user", "/run/systemd/system", "/run/systemd/user", "/lib/systemd/system", "/lib/systemd/user"}
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
