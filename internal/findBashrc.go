package internal

import (
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
)

func CheckBashrc(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info().Msg("Checking .bashrc Files...")
	files, err := filepath.Glob("/home/*/.bashrc")
	files = append(files, "/root/.bashrc")
	if err != nil {
		logger.Error().Err(err)
		return
	}
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
	patternMatch:
		for _, pattern := range suspiciousPatterns {
			if helpers.SearchStringContains(fileContents, pattern) {
				tmp_ := map[string]interface{}{
					"Modified": fileModificationTime,
					"Pattern":  pattern,
					"File":     file,
				}
				detection := Detection{
					Name:      "Suspicious Pattern in .bashrc File",
					Severity:  2,
					Tip:       "Investigate file to determine validity.",
					Technique: "T1546.004",
					Metadata:  tmp_,
				}
				detections <- detection
				break patternMatch
			}
		}

	}
}
