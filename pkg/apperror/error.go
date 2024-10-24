package apperror

import (
	"arch/internal/model"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

const (
	statusMessageMin = 100
	statusMessageMax = 511
)

type ErrorValidation struct {
	Field          string `json:"field"`
	ValidationCode string `json:"validation_code"`
	Param          string `json:"param"`
	Message        string `json:"message"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error makes it compatible with the `error` interface.
func (e *Error) Error() string {
	return e.Message
}

func NewAppError(code int, message ...string) *Error {
	err := &Error{
		Code:    code,
		Message: StatusMessage(code),
	}
	if len(message) > 0 {
		err.Message = message[0]
	}
	return err
}

func StatusMessage(status int) string {
	if status < statusMessageMin || status > statusMessageMax {
		return ""
	}
	return statusMessage[status]
}

func HandleError(ctx *fiber.Ctx, log *logrus.Logger, err error) error {
	// If the error is a CustomError, return the custom status code and message
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		return ErrorBindingResponse(ctx, validationErrors)
	} else if customErr, ok := err.(*Error); ok {
		return ctx.Status(customErr.Code).JSON(model.WebResponse[any]{Message: customErr.Message})
	}
	// For all other errors, return a generic internal server error response
	return ctx.Status(http.StatusInternalServerError).JSON(model.WebResponse[any]{Message: err.Error()})
}

func ErrorBindingResponse(ctx *fiber.Ctx, validationErrors validator.ValidationErrors) error {
	var responseErrors []ErrorValidation
	for _, fieldError := range validationErrors {
		field := fieldError.Field()
		responseErrors = append(responseErrors, ErrorValidation{
			Field:          strings.ToLower(field),
			ValidationCode: strings.ToUpper(fieldError.Tag()),
			Param:          fieldError.Param(),
			Message:        ParseFieldError(fieldError),
		})
	}
	return ctx.Status(http.StatusUnprocessableEntity).JSON(model.WebResponse[any]{
		Message: "validasi error",
		Errors:  responseErrors,
	})
}

func ParseFieldError(e validator.FieldError) string {
	fieldPrefix := strings.ToLower(e.Field())
	tag := strings.Split(e.Tag(), "|")[0]
	switch tag {
	case "required":
		return fmt.Sprintf("%s wajib diisi", fieldPrefix)
	case "email":
		return fmt.Sprintf("%s harus berupa email", fieldPrefix)
	case "min":
		return fmt.Sprintf("%s minimal %s karakter", fieldPrefix, e.Param())
	case "gte":
		return fmt.Sprintf("%s harus lebih besar atau sama dengan %s", fieldPrefix, e.Param())
	case "let":
		return fmt.Sprintf("%s harus kurang dari atau sama dengan %s", fieldPrefix, e.Param())
	default:
		return fmt.Errorf("%v", e).Error()
	}
}

// NOTE: Keep this in sync with the status code list
var statusMessage = []string{
	100: "Continue",            // StatusContinue
	101: "Switching Protocols", // StatusSwitchingProtocols
	102: "Processing",          // StatusProcessing
	103: "Early Hints",         // StatusEarlyHints

	200: "OK",                            // StatusOK
	201: "Created",                       // StatusCreated
	202: "Accepted",                      // StatusAccepted
	203: "Non-Authoritative Information", // StatusNonAuthoritativeInformation
	204: "No Content",                    // StatusNoContent
	205: "Reset Content",                 // StatusResetContent
	206: "Partial Content",               // StatusPartialContent
	207: "Multi-Status",                  // StatusMultiStatus
	208: "Already Reported",              // StatusAlreadyReported
	226: "IM Used",                       // StatusIMUsed

	300: "Multiple Choices",   // StatusMultipleChoices
	301: "Moved Permanently",  // StatusMovedPermanently
	302: "Found",              // StatusFound
	303: "See Other",          // StatusSeeOther
	304: "Not Modified",       // StatusNotModified
	305: "Use Proxy",          // StatusUseProxy
	306: "Switch Proxy",       // StatusSwitchProxy
	307: "Temporary Redirect", // StatusTemporaryRedirect
	308: "Permanent Redirect", // StatusPermanentRedirect

	400: "Bad Request",                     // StatusBadRequest
	401: "Unauthorized",                    // StatusUnauthorized
	402: "Payment Required",                // StatusPaymentRequired
	403: "Forbidden",                       // StatusForbidden
	404: "Not Found",                       // StatusNotFound
	405: "Method Not Allowed",              // StatusMethodNotAllowed
	406: "Not Acceptable",                  // StatusNotAcceptable
	407: "Proxy Authentication Required",   // StatusProxyAuthRequired
	408: "Request Timeout",                 // StatusRequestTimeout
	409: "Conflict",                        // StatusConflict
	410: "Gone",                            // StatusGone
	411: "Length Required",                 // StatusLengthRequired
	412: "Precondition Failed",             // StatusPreconditionFailed
	413: "Request Entity Too Large",        // StatusRequestEntityTooLarge
	414: "Request URI Too Long",            // StatusRequestURITooLong
	415: "Unsupported Media Type",          // StatusUnsupportedMediaType
	416: "Requested Range Not Satisfiable", // StatusRequestedRangeNotSatisfiable
	417: "Expectation Failed",              // StatusExpectationFailed
	418: "I'm a teapot",                    // StatusTeapot
	421: "Misdirected Request",             // StatusMisdirectedRequest
	422: "Unprocessable Entity",            // StatusUnprocessableEntity
	423: "Locked",                          // StatusLocked
	424: "Failed Dependency",               // StatusFailedDependency
	425: "Too Early",                       // StatusTooEarly
	426: "Upgrade Required",                // StatusUpgradeRequired
	428: "Precondition Required",           // StatusPreconditionRequired
	429: "Too Many Requests",               // StatusTooManyRequests
	431: "Request Header Fields Too Large", // StatusRequestHeaderFieldsTooLarge
	451: "Unavailable For Legal Reasons",   // StatusUnavailableForLegalReasons

	500: "Internal Server Error",           // StatusInternalServerError
	501: "Not Implemented",                 // StatusNotImplemented
	502: "Bad Gateway",                     // StatusBadGateway
	503: "Service Unavailable",             // StatusServiceUnavailable
	504: "Gateway Timeout",                 // StatusGatewayTimeout
	505: "HTTP Version Not Supported",      // StatusHTTPVersionNotSupported
	506: "Variant Also Negotiates",         // StatusVariantAlsoNegotiates
	507: "Insufficient Storage",            // StatusInsufficientStorage
	508: "Loop Detected",                   // StatusLoopDetected
	510: "Not Extended",                    // StatusNotExtended
	511: "Network Authentication Required", // StatusNetworkAuthenticationRequired
}
