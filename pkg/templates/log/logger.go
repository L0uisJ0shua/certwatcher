package templates

import (
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "time"
)

type CertLogger struct {
    logFile *os.File
    mu      sync.Mutex
}

type LogEntry struct {
    Timestamp string `json:"timestamp"`
    Message   string `json:"message"`
}

// New cria um novo objeto CertLogger e inicializa o arquivo de log.
func New(logFilePath string) (*CertLogger, error) {
    logFilePath = resolveLogFilePath(logFilePath)

    logFile, err := createLogFile(logFilePath)
    if err != nil {
        return nil, fmt.Errorf("error creating log file: %s", err)
    }

    logger := &CertLogger{
        logFile: logFile,
    }

    return logger, nil
}

// resolveLogFilePath resolve o caminho do arquivo de log, criando-o no diretório home do usuário, se necessário.
func resolveLogFilePath(logFilePath string) string {
    if logFilePath == "" {
        homeDir, err := os.UserHomeDir()
        if err != nil {
            logFilePath = "certwatcher.log" // Fallback to default log file name
        } else {
            logFilePath = filepath.Join(homeDir, "certwatcher.log")
        }
    }
    return logFilePath
}

// createLogFile cria o arquivo de log e os diretórios necessários no caminho.
func createLogFile(logFilePath string) (*os.File, error) {
    err := os.MkdirAll(filepath.Dir(logFilePath), os.ModePerm)
    if err != nil {
        return nil, fmt.Errorf("error creating log directories: %s", err)
    }

    logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return nil, fmt.Errorf("error opening log file: %s", err)
    }

    return logFile, nil
}

// WriteLog escreve uma mensagem de log no arquivo de log.
func (logger *CertLogger) WriteLog(message string) error {
    logger.mu.Lock()
    defer logger.mu.Unlock()

    timestamp := time.Now().Format("2006-01-02 15:04:05")
    logEntry := fmt.Sprintf("[%s] %s\n", timestamp, message)

    // Write the log message to the file
    _, err := logger.logFile.WriteString(logEntry)
    if err != nil {
        return fmt.Errorf("error writing to log file: %s", err)
    }

    return nil
}

// Close fecha o arquivo de log.
func (logger *CertLogger) Close() error {
    logger.mu.Lock()
    defer logger.mu.Unlock()

    err := logger.logFile.Close()
    if err != nil {
        return fmt.Errorf("error closing log file: %s", err)
    }
    return nil
}
