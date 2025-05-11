package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// ErrorSeverity defines the severity level of errors
type ErrorSeverity int

const (
	// SeverityInfo represents informational messages
	SeverityInfo ErrorSeverity = iota
	// SeverityWarning represents warning messages
	SeverityWarning
	// SeverityError represents error messages
	SeverityError
	// SeverityCritical represents critical errors
	SeverityCritical
	// SeverityFatal represents fatal errors
	SeverityFatal
)

// ErrorCategory defines the category of errors
type ErrorCategory string

const (
	// CategorySystem for system-related errors
	CategorySystem ErrorCategory = "SYSTEM"
	// CategoryNetwork for network-related errors
	CategoryNetwork ErrorCategory = "NETWORK"
	// CategorySecurity for security-related errors
	CategorySecurity ErrorCategory = "SECURITY"
	// CategoryDatabase for database-related errors
	CategoryDatabase ErrorCategory = "DATABASE"
	// CategoryUI for UI-related errors
	CategoryUI ErrorCategory = "UI"
	// CategoryAPI for API-related errors
	CategoryAPI ErrorCategory = "API"
	// CategoryPersistence for persistence-related errors
	CategoryPersistence ErrorCategory = "PERSISTENCE"
	// CategoryMonitoring for monitoring-related errors
	CategoryMonitoring ErrorCategory = "MONITORING"
)

// EnterpriseError represents an enterprise-grade error with detailed information
type EnterpriseError struct {
	// Basic error information
	Code        string        `json:"code"`
	Message     string        `json:"message"`
	Severity    ErrorSeverity `json:"severity"`
	Category    ErrorCategory `json:"category"`
	Timestamp   time.Time     `json:"timestamp"`
	ContextData interface{}   `json:"context_data,omitempty"`
	
	// Technical details
	OriginalError error         `json:"-"`
	StackTrace    string        `json:"stack_trace,omitempty"`
	FileName      string        `json:"file_name,omitempty"`
	LineNumber    int           `json:"line_number,omitempty"`
	FunctionName  string        `json:"function_name,omitempty"`
	
	// Recovery information
	Recoverable   bool          `json:"recoverable"`
	RecoveryHint  string        `json:"recovery_hint,omitempty"`
	RetryAttempts int           `json:"retry_attempts,omitempty"`
	RetryDelay    time.Duration `json:"retry_delay,omitempty"`
}

// ErrorManager handles enterprise-grade error management
type ErrorManager struct {
	// Error storage
	Errors         []EnterpriseError
	ErrorsByCode   map[string][]EnterpriseError
	ErrorsByCategory map[string][]EnterpriseError
	
	// Configuration
	MaxErrors      int
	EnableLogging  bool
	LogPath        string
	
	// Metrics
	ErrorCount     int
	WarningCount   int
	CriticalCount  int
	FatalCount     int
	
	// Lock for concurrent access
	mutex          sync.RWMutex
}

// NewErrorManager creates a new error manager
func NewErrorManager() *ErrorManager {
	manager := &ErrorManager{
		Errors:         make([]EnterpriseError, 0),
		ErrorsByCode:   make(map[string][]EnterpriseError),
		ErrorsByCategory: make(map[string][]EnterpriseError),
		MaxErrors:      1000,
		EnableLogging:  true,
		LogPath:        "logs/errors",
	}
	
	// Create log directory
	os.MkdirAll(manager.LogPath, 0755)
	
	return manager
}

// NewError creates a new enterprise error
func (em *ErrorManager) NewError(code string, message string, severity ErrorSeverity, category ErrorCategory, originalError error) *EnterpriseError {
	// Create basic error
	enterpriseErr := EnterpriseError{
		Code:         code,
		Message:      message,
		Severity:     severity,
		Category:     category,
		Timestamp:    time.Now(),
		OriginalError: originalError,
		Recoverable:  severity < SeverityCritical,
	}
	
	// Get stack trace and caller information
	stackTrace := debug.Stack()
	enterpriseErr.StackTrace = string(stackTrace)
	
	// Get caller information
	if pc, file, line, ok := runtime.Caller(2); ok {
		enterpriseErr.FileName = filepath.Base(file)
		enterpriseErr.LineNumber = line
		
		if fn := runtime.FuncForPC(pc); fn != nil {
			enterpriseErr.FunctionName = fn.Name()
		}
	}
	
	// Set default retry information based on severity
	switch severity {
	case SeverityInfo, SeverityWarning:
		enterpriseErr.RetryAttempts = 0
	case SeverityError:
		enterpriseErr.RetryAttempts = 3
		enterpriseErr.RetryDelay = 5 * time.Second
		enterpriseErr.RecoveryHint = "This operation can be retried automatically."
	case SeverityCritical:
		enterpriseErr.RetryAttempts = 1
		enterpriseErr.RetryDelay = 30 * time.Second
		enterpriseErr.RecoveryHint = "This operation requires system intervention but will attempt recovery."
	case SeverityFatal:
		enterpriseErr.Recoverable = false
		enterpriseErr.RecoveryHint = "This operation cannot be recovered automatically and requires manual intervention."
	}
	
	return &enterpriseErr
}

// LogError logs an error to the error manager
func (em *ErrorManager) LogError(err *EnterpriseError) {
	em.mutex.Lock()
	defer em.mutex.Unlock()
	
	// Add to main error list
	em.Errors = append(em.Errors, *err)
	
	// Add to error code map
	em.ErrorsByCode[err.Code] = append(em.ErrorsByCode[err.Code], *err)
	
	// Add to category map
	category := string(err.Category)
	em.ErrorsByCategory[category] = append(em.ErrorsByCategory[category], *err)
	
	// Update metrics
	switch err.Severity {
	case SeverityError:
		em.ErrorCount++
	case SeverityWarning:
		em.WarningCount++
	case SeverityCritical:
		em.CriticalCount++
	case SeverityFatal:
		em.FatalCount++
	}
	
	// Truncate if needed
	if len(em.Errors) > em.MaxErrors {
		em.Errors = em.Errors[len(em.Errors)-em.MaxErrors:]
	}
	
	// Write to log file if enabled
	if em.EnableLogging {
		em.writeErrorToLog(err)
	}
	
	// Log to activity log
	logActivity(fmt.Sprintf("[%s] %s: %s", err.Category, err.Code, err.Message))
}

// WriteErrorToLog writes an error to the log file
func (em *ErrorManager) writeErrorToLog(err *EnterpriseError) {
	// Create directory if it doesn't exist
	os.MkdirAll(em.LogPath, 0755)
	
	// Create filename based on date
	filename := filepath.Join(em.LogPath, fmt.Sprintf("error-%s.log", time.Now().Format("2006-01-02")))
	
	// Format error as JSON
	errorJSON, _ := json.MarshalIndent(err, "", "  ")
	
	// Append to file
	file, fileErr := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if fileErr != nil {
		return
	}
	defer file.Close()
	
	// Write with timestamp and separator
	file.WriteString(fmt.Sprintf("=== ERROR EVENT AT %s ===\n", err.Timestamp.Format(time.RFC3339)))
	file.Write(errorJSON)
	file.WriteString("\n\n")
}

// GetErrorsByCode returns errors by error code
func (em *ErrorManager) GetErrorsByCode(code string) []EnterpriseError {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	
	if errors, ok := em.ErrorsByCode[code]; ok {
		return errors
	}
	
	return []EnterpriseError{}
}

// GetErrorsByCategory returns errors by category
func (em *ErrorManager) GetErrorsByCategory(category ErrorCategory) []EnterpriseError {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	
	if errors, ok := em.ErrorsByCategory[string(category)]; ok {
		return errors
	}
	
	return []EnterpriseError{}
}

// GetErrorsSummary returns a summary of errors by category
func (em *ErrorManager) GetErrorsSummary() map[string]int {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	
	summary := make(map[string]int)
	
	for category, errors := range em.ErrorsByCategory {
		summary[category] = len(errors)
	}
	
	return summary
}

// GetErrorMetrics returns metrics about errors
func (em *ErrorManager) GetErrorMetrics() map[string]int {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	
	return map[string]int{
		"total":      len(em.Errors),
		"errors":     em.ErrorCount,
		"warnings":   em.WarningCount,
		"critical":   em.CriticalCount,
		"fatal":      em.FatalCount,
	}
}

// ClearErrors clears all errors
func (em *ErrorManager) ClearErrors() {
	em.mutex.Lock()
	defer em.mutex.Unlock()
	
	em.Errors = make([]EnterpriseError, 0)
	em.ErrorsByCode = make(map[string][]EnterpriseError)
	em.ErrorsByCategory = make(map[string][]EnterpriseError)
	em.ErrorCount = 0
	em.WarningCount = 0
	em.CriticalCount = 0
	em.FatalCount = 0
}

// ExportErrorsToFile exports all errors to a file
func (em *ErrorManager) ExportErrorsToFile(filepath string) error {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	
	// Convert errors to JSON
	errorsJSON, err := json.MarshalIndent(em.Errors, "", "  ")
	if err != nil {
		return err
	}
	
	// Write to file
	return ioutil.WriteFile(filepath, errorsJSON, 0644)
}

// Error returns the error message
func (e *EnterpriseError) Error() string {
	return fmt.Sprintf("[%s-%s] %s", e.Category, e.Code, e.Message)
}

// GetOriginalError returns the original error
func (e *EnterpriseError) GetOriginalError() error {
	return e.OriginalError
}

// FormatDetail returns a detailed error message
func (e *EnterpriseError) FormatDetail() string {
	var builder strings.Builder
	
	builder.WriteString(fmt.Sprintf("=== ZLT Enterprise Error Report ===\n"))
	builder.WriteString(fmt.Sprintf("Error Code: %s\n", e.Code))
	builder.WriteString(fmt.Sprintf("Message: %s\n", e.Message))
	builder.WriteString(fmt.Sprintf("Category: %s\n", e.Category))
	builder.WriteString(fmt.Sprintf("Severity: %d\n", e.Severity))
	builder.WriteString(fmt.Sprintf("Timestamp: %s\n", e.Timestamp.Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("Location: %s:%d\n", e.FileName, e.LineNumber))
	builder.WriteString(fmt.Sprintf("Function: %s\n", e.FunctionName))
	builder.WriteString(fmt.Sprintf("Recoverable: %t\n", e.Recoverable))
	
	if e.RecoveryHint != "" {
		builder.WriteString(fmt.Sprintf("Recovery Hint: %s\n", e.RecoveryHint))
	}
	
	if e.OriginalError != nil {
		builder.WriteString(fmt.Sprintf("Original Error: %v\n", e.OriginalError))
	}
	
	builder.WriteString("=== End of Error Report ===\n")
	
	return builder.String()
}

// IsRecoverable returns whether the error is recoverable
func (e *EnterpriseError) IsRecoverable() bool {
	return e.Recoverable
}

// ShouldRetry returns whether the error should be retried
func (e *EnterpriseError) ShouldRetry(attemptsMade int) bool {
	return e.Recoverable && attemptsMade < e.RetryAttempts
}

// GetRetryDelay returns the retry delay
func (e *EnterpriseError) GetRetryDelay() time.Duration {
	return e.RetryDelay
}

// WithContext adds context data to the error
func (e *EnterpriseError) WithContext(contextData interface{}) *EnterpriseError {
	e.ContextData = contextData
	return e
}

// WithRecoveryInfo sets recovery information for the error
func (e *EnterpriseError) WithRecoveryInfo(recoverable bool, hint string, retryAttempts int, retryDelay time.Duration) *EnterpriseError {
	e.Recoverable = recoverable
	e.RecoveryHint = hint
	e.RetryAttempts = retryAttempts
	e.RetryDelay = retryDelay
	return e
}

// -----------------------------
// Global error manager instance
// -----------------------------
var (
	globalErrorManager *ErrorManager
	errorManagerInit   sync.Once
)

// GetErrorManager returns the global error manager instance
func GetErrorManager() *ErrorManager {
	errorManagerInit.Do(func() {
		globalErrorManager = NewErrorManager()
	})
	
	return globalErrorManager
}

// -----------------------------
// Helper functions for error handling
// -----------------------------

// LogErrorf creates and logs an error with formatting
func LogErrorf(code string, category ErrorCategory, severity ErrorSeverity, format string, args ...interface{}) *EnterpriseError {
	message := fmt.Sprintf(format, args...)
	var originalError error
	if len(args) > 0 {
		if err, ok := args[len(args)-1].(error); ok {
			originalError = err
		}
	}
	
	err := GetErrorManager().NewError(code, message, severity, category, originalError)
	GetErrorManager().LogError(err)
	return err
}

// LogSystemError logs a system error
func LogSystemError(code string, message string, originalError error) *EnterpriseError {
	err := GetErrorManager().NewError(code, message, SeverityError, CategorySystem, originalError)
	GetErrorManager().LogError(err)
	return err
}

// LogNetworkError logs a network error
func LogNetworkError(code string, message string, originalError error) *EnterpriseError {
	err := GetErrorManager().NewError(code, message, SeverityError, CategoryNetwork, originalError)
	GetErrorManager().LogError(err)
	return err
}

// LogSecurityError logs a security error
func LogSecurityError(code string, message string, originalError error) *EnterpriseError {
	err := GetErrorManager().NewError(code, message, SeverityError, CategorySecurity, originalError)
	GetErrorManager().LogError(err)
	return err
}

// LogCriticalError logs a critical error
func LogCriticalError(code string, category ErrorCategory, message string, originalError error) *EnterpriseError {
	err := GetErrorManager().NewError(code, message, SeverityCritical, category, originalError)
	GetErrorManager().LogError(err)
	return err
}

// LogFatalError logs a fatal error
func LogFatalError(code string, category ErrorCategory, message string, originalError error) *EnterpriseError {
	err := GetErrorManager().NewError(code, message, SeverityFatal, category, originalError)
	GetErrorManager().LogError(err)
	return err
}

// WithRetry executes a function with retry logic
func WithRetry(fn func() error, maxAttempts int, delay time.Duration) error {
	var err error
	
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}
		
		// Log retry attempt
		if attempt < maxAttempts-1 {
			logActivity(fmt.Sprintf("Retrying operation (attempt %d/%d) after error: %v", 
				attempt+1, maxAttempts, err))
			time.Sleep(delay)
			
			// Exponential backoff
			delay = delay * 2
		}
	}
	
	return err
}