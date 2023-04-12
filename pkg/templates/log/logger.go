package templates

import (
    "fmt"
    "os"
    "time"
)

type CertLogger struct {
    logFile *os.File
}

// Initializes a new CertLogger object
func New(logFilePath string) (*CertLogger, error) {
    // Check if the log file exists. If not, create it.
    _, err := os.Stat(logFilePath)
    if os.IsNotExist(err) {
        f, err := os.Create(logFilePath)
        if err != nil {
            return nil, fmt.Errorf("error creating log file: %s", err)
        }
        f.Close()
    }

    // Open the log file for appending
    logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        return nil, fmt.Errorf("error opening log file: %s", err)
    }

    // Create the CertLogger object
    logger := &CertLogger{logFile: logFile}

    return logger, nil
}

// Writes a log message to the log file
func (logger *CertLogger) WriteLog(message string) error {
    // Create a timestamp for the log entry
    timestamp := time.Now().Format("2006-01-02 15:04:05")

    // Write the log message to the file
    _, err := logger.logFile.WriteString(fmt.Sprintf("[%s] %s\n", timestamp, message))
    if err != nil {
        return fmt.Errorf("error writing to log file: %s", err)
    }

    return nil
}

// Closes the log file
func (logger *CertLogger) Close() error {
    return logger.logFile.Close()
}
