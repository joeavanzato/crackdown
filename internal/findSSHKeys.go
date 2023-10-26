package internal

import (
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/rs/zerolog"
	"path/filepath"
	"strings"
)

func FindSSHAuthorizedKeys(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	// TODO - Add additional possible properties to detection metadata
	logger.Info().Msg("Finding Authorized SSH Keys...")
	files, err := filepath.Glob("/home/*/.ssh/authorized_keys")
	if err != nil {
		logger.Error().Err(err)
		return
	}
	validKeyTypes := []string{
		"ssh-dss", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2- nistp384", "ecdsa-sha2-nistp521", "ssh-ed25519",
	}
	for _, file := range files {
		lines := helpers.ReadFileToSlice(file, logger)
		for _, l := range lines {
			keySplit := strings.Split(strings.TrimSpace(l), " ")
			if keySplit[0] == "" {
				continue
			}
			keyTypeExists := false
			keyType := ""
			keyName := ""
			for _, v := range keySplit {
				if helpers.SliceContains(validKeyTypes, v) {
					keyType = v
					keyTypeExists = true
				}
			}
			keyName = keySplit[len(keySplit)-1]
			if len(keyName) > 30 {
				// We can probably assume this is actually the public key data rather than the 'name'
				keyName = ""
			}
			if keyTypeExists == true {
				tmp_ := map[string]interface{}{
					"KeyType": strings.TrimSpace(keyType),
					"KeyName": strings.TrimSpace(keyName),
					"File":    strings.TrimSpace(file),
				}
				detection := Detection{
					Name:      "SSH Key Review",
					Severity:  0,
					Tip:       "Verify validity of authorized key",
					Technique: "T1098.004",
					Metadata:  tmp_,
				}
				detections <- detection
			}
		}
	}

}
