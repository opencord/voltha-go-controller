package log

import (
	"context"

	"github.com/opencord/voltha-lib-go/v7/pkg/log"
)

const skipLevel = 2

//Fields - struct to update log params
type Fields log.Fields

//CLogger - CLogger  wrapper
type CLogger struct {
	clogger log.CLogger
}

type LogLevel int8

// constants defining the Log Level
const (
	// DebugLevel logs a message at debug level
	DebugLevel = iota
	// InfoLevel logs a message at info level
	InfoLevel
	// WarnLevel logs a message at warning level
	WarnLevel
	// ErrorLevel logs a message at error level
	ErrorLevel
	// FatalLevel logs a message, then calls os.Exit(1).
	FatalLevel
)

// AddPackageWithDefaultParam registers a package to the log map with default params
func AddPackageWithDefaultParam() (CLogger, error) {
	var cLogger CLogger
	_, err := log.RegisterPackage(log.JSON, log.ErrorLevel, log.Fields{})
	if err == nil {
		cLogger.clogger, _ = log.UpdateCallerSkipLevel(skipLevel)
	}
	return cLogger, err
}

// AddPackage registers a package to the log map
func AddPackage(level int) (*CLogger, error) {
	var cLogger *CLogger
	logger, err := log.RegisterPackage(log.JSON, log.LogLevel(level), log.Fields{})
	if err == nil {
		cLogger = &CLogger{
			clogger: logger,
		}
	}
	return cLogger, err
}

//StringToLogLevel - converts the log level  from string to defined uint8
func StringToLogLevel(l string) (LogLevel, error) {
	ll, err := log.StringToLogLevel(l)
	if err != nil {
		return 0, err
	}
	return LogLevel(ll), nil
}

// With initializes logger with the key-value pairs
func (cl CLogger) With(ctx context.Context, keysAndValues Fields, msg string) {
	cl.clogger.With(log.Fields(keysAndValues)).Fatal(ctx, msg)
}

// SetAllLogLevel sets the log level of all registered packages to level
func SetAllLogLevel(level int) {
	log.SetAllLogLevel(log.LogLevel(level))
}

// SetDefaultLogLevel sets the log level used for packages that don't have specific loggers
func SetDefaultLogLevel(level int) {
	log.SetDefaultLogLevel(log.LogLevel(level))
}

// UpdateAllLoggers create new loggers for all registered pacakges with the defaultFields.
func UpdateAllLoggers(defaultFields Fields) error {
	_ = log.UpdateAllLoggers(log.Fields(defaultFields))
	return log.UpdateAllCallerSkipLevel(skipLevel)
}

// SetDefaultLogger needs to be invoked before the logger API can be invoked.  This function
// initialize the default logger (zap's sugaredlogger)
func SetDefaultLogger(ctx context.Context, level int, defaultFields Fields) error {
	_, err := log.SetDefaultLogger(log.JSON, log.LogLevel(level), log.Fields(defaultFields))
	return err
}

// CleanUp flushed any buffered log entries. Applications should take care to call
// CleanUp before exiting.
func CleanUp() error {
	return log.CleanUp()
}

// Fatal logs a message at level Fatal on the standard logger.
func (cl CLogger) Fatal(ctx context.Context, args string) {
	cl.clogger.Fatal(ctx, args)
}

// Fatalw logs a message with some additional context. The variadic key-value
// pairs are treated as they are in With.
func (cl CLogger) Fatalw(ctx context.Context, msg string, keysAndValues Fields) {
	cl.clogger.Fatalw(ctx, msg, log.Fields(keysAndValues))

}

// Error logs a message at level Error on the standard logger.
func (cl CLogger) Error(ctx context.Context, args string) {
	cl.clogger.Error(ctx, args)
}

// Errorw logs a message with some additional context. The variadic key-value
// pairs are treated as they are in With.
func (cl CLogger) Errorw(ctx context.Context, msg string, keysAndValues Fields) {
	cl.clogger.Errorw(ctx, msg, log.Fields(keysAndValues))
}

// Warn logs a message at level Warn on the standard logger.
func (cl CLogger) Warn(ctx context.Context, args string) {
	cl.clogger.Warn(ctx, args)
}

// Warnw logs a message with some additional context. The variadic key-value
// pairs are treated as they are in With.
func (cl CLogger) Warnw(ctx context.Context, msg string, keysAndValues Fields) {
	cl.clogger.Warnw(ctx, msg, log.Fields(keysAndValues))
}

// Info logs a message at level Info on the standard logger.
func (cl CLogger) Info(ctx context.Context, args string) {
	cl.clogger.Info(ctx, args)
}

// Infow logs a message with some additional context. The variadic key-value
// pairs are treated as they are in With.
func (cl CLogger) Infow(ctx context.Context, msg string, keysAndValues Fields) {
	cl.clogger.Infow(ctx, msg, log.Fields(keysAndValues))
}

// Debug logs a message at level Debug on the standard logger.
func (cl CLogger) Debug(ctx context.Context, args string) {
	cl.clogger.Debug(ctx, args)
}

// Debugw logs a message with some additional context. The variadic key-value
// pairs are treated as they are in With.
func (cl CLogger) Debugw(ctx context.Context, msg string, keysAndValues Fields) {
	cl.clogger.Debugw(ctx, msg, log.Fields(keysAndValues))
}
