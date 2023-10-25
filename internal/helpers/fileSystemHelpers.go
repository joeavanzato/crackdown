package helpers

import (
	"bufio"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"strings"
)

func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func ReadFileToSlice(filename string, logger *logrus.Logger) []string {
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		logger.Error(err)
		return make([]string, 0)
	}
	reader := bufio.NewReader(file)
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		lines = append(lines, strings.TrimSpace(line))
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Error(err)
			return make([]string, 0)
		}
	}
	return lines
	//reader := bufio.NewReader(file)
}

func ReadFileToString(filename string, logger *logrus.Logger) string {
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		logger.Error(err)
		return ""
	}
	reader := bufio.NewReader(file)
	var lines string
	for {
		line, err := reader.ReadString('\n')
		lines += strings.TrimSpace(line)
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Error(err)
			return ""
		}
	}
	return lines
	//reader := bufio.NewReader(file)
}
