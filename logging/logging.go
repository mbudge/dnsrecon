package logging

import (
	"log"
	"os"
)

var (
	Trace   *log.Logger
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
)

func NewLogger() *log.Logger {

	logFile := log.New(os.Stderr, "", 0)

	return logFile

}
