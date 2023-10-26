package internal

import (
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/rs/zerolog"
	"io/fs"
	"path/filepath"
	"strings"
)

// TODO - Scan /var/www/html, /etc/nginx, /etc/apache2 for suspicious files, recently created.
var webshellFilePaths = make([]string, 10)
var webshellExtensions = []string{
	".aar",
	".ascx",
	".ashx",
	".asmx",
	".asp",
	".aspx",
	".cfm",
	".cgi",
	".js",
	".jsp",
	".jspx",
	".php",
	".jar",
}

func FindWebShells(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info().Msg("Finding Web Shells...")
	getWebshellFiles(logger)
	for _, v := range webshellFilePaths {
		if v == "" {
			continue
		}
		lastModified := "NA"
		lastModifiedTimestamp, err := helpers.GetFileLastModified(v, logger)
		if err == nil {
			lastModified = lastModifiedTimestamp.String()
		}

		tmp_ := map[string]interface{}{
			"File":         strings.TrimSpace(v),
			"LastModified": lastModified,
		}
		detection := Detection{
			Name:      "",
			Severity:  2,
			Tip:       "Verify validity of web-based file.",
			Technique: "T1505.003",
			Metadata:  tmp_,
		}
		fileLines := helpers.ReadFileToSlice(v, logger)
	fileScan:
		for _, line := range fileLines {
			detection.Metadata["Line"] = line

			detection.Name = "Potential Webshell - Webshell Pattern in Content"
			result := checkWebshellContent(detection, detections, line)
			if result {
				break fileScan
			}

			detection.Name = "Potential Webshell - Suspicious Pattern in Content"
			result = checkSuspiciousContent(detection, detections, line)
			if result {
				break fileScan
			}
			detection.Name = "Potential Webshell - IP Address patterrn in Content"
			result = checkIPContent(detection, detections, line)
			if result {
				break fileScan
			}
			detection.Name = "Potential Webshell - Domain pattern in Content"
			result = checkDomainContent(detection, detections, line)
			if result {
				break fileScan
			}
		}
	}
}

func getWebshellFiles(logger zerolog.Logger) {
	webshellDirs := []string{
		"/var/www/html",
		"/etc/nginx",
		"/etc/apache*",
	}
	for _, path := range webshellDirs {
		filepath.WalkDir(path, walkWebShells)
	}
}

func walkWebShells(s string, d fs.DirEntry, err error) error {
	if err != nil {
		return err
	}
	if !d.IsDir() && helpers.SliceContains(webshellExtensions, s) {
		webshellFilePaths = append(webshellFilePaths, s)
	}
	return nil
}
