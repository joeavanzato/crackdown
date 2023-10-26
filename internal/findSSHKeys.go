package internal

import (
	"github.com/rs/zerolog"
	"path/filepath"
)

func FindSSHAuthorizedKeys(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info().Msg("Finding Authorized SSH Keys...")
	files, err := filepath.Glob("/home/*/.ssh/authorized_keys")
	if err != nil {
		logger.Error().Err(err)
		return
	}
	for _, file := range files {
		logger.Info().Msg(file)
	}

}
