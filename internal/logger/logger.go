package logger

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

var currentLevel Level = LevelInfo

func Init(levelStr string) {
	switch strings.ToLower(levelStr) {
	case "debug":
		currentLevel = LevelDebug
	case "info":
		currentLevel = LevelInfo
	case "warn", "warning":
		currentLevel = LevelWarn
	case "error":
		currentLevel = LevelError
	default:
		currentLevel = LevelInfo
	}
}

func log(level Level, levelName, color string, format string, args ...interface{}) {
	if level < currentLevel {
		return
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stdout, "%s%s%s %s[%s]%s %s\n",
		colorGray, timestamp, colorReset,
		color, levelName, colorReset,
		msg)
}

func Debug(format string, args ...interface{}) {
	log(LevelDebug, "DEBUG", colorCyan, format, args...)
}

func Info(format string, args ...interface{}) {
	log(LevelInfo, "INFO", colorGreen, format, args...)
}

func Warn(format string, args ...interface{}) {
	log(LevelWarn, "WARN", colorYellow, format, args...)
}

func Error(format string, args ...interface{}) {
	log(LevelError, "ERROR", colorRed, format, args...)
}

func Fatal(format string, args ...interface{}) {
	log(LevelError, "FATAL", colorRed, format, args...)
	os.Exit(1)
}
