package govulners

import "net/http"

type Logger interface {
	Println(v ...interface{})
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Options struct {
	logger     Logger
	httpClient HTTPClient
}

type Option func(*Options)

// WithLogger - set logger
func WithLogger(logger Logger) Option {
	return func(o *Options) {
		o.logger = logger
	}
}

// WithHttpClient - set custom http client
func WithHttpClient(httpClient HTTPClient) Option {
	return func(o *Options) {
		o.httpClient = httpClient
	}
}
