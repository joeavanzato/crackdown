package internal

import (
	"bufio"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"os/user"
	"strings"
)

func FindLocalUsers(logger *logrus.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	// https://socketloop.com/tutorials/golang-get-all-local-users-and-print-out-their-home-directory-description-and-group-id
	defer waitGroup.Done()
	logger.Info("Finding Local Users...")
	file, err := os.Open("/etc/passwd")
	defer file.Close()
	if err != nil {
		logger.Error(err)
		return
	}
	// TODO - Abstract the reading of file away from user extraction
	reader := bufio.NewReader(file)
	var Users []string
	for {
		line, err := reader.ReadString('\n')
		if equal := strings.Index(line, "#"); equal < 0 {
			lineSlice := strings.FieldsFunc(line, func(divide rune) bool {
				return divide == ':'
			})
			if len(lineSlice) > 0 {
				Users = append(Users, lineSlice[0])
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Error(err)
			return
		}
	}
	for _, name := range Users {
		usr, err := user.Lookup(name)
		if err != nil {
			logger.Error(err)
		}

		tmp_ := map[string]string{
			"Username":     strings.TrimSpace(usr.Username),
			"_HomeDir":     strings.TrimSpace(usr.HomeDir),
			"_GroupID":     strings.TrimSpace(usr.Gid),
			"_DisplayName": strings.TrimSpace(usr.Name),
		}
		detection := Detection{
			Name:      "Local User Account",
			Severity:  0,
			Tip:       "Verify validity of user account.",
			Technique: "T1136.001",
			Metadata:  tmp_,
		}
		//detections = append(detections, detection)
		detections <- detection
		//logger.Info(detection)
		/*fmt.Printf("username:%s\n", usr.Username)
		fmt.Printf("homedir:%s\n", usr.HomeDir)
		fmt.Printf("groupID:%s\n", usr.Gid)
		fmt.Printf("DisplayName:%s\n", usr.Name)
		fmt.Println("*********************************")*/

	}
	return
}
