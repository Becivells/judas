package judas

import (
	"log"
	"net/http"
	"net/url"
)

// Config holds all program configuration required to spin up a functioning instance of Judas.
type Config struct {
	TargetURL      *url.URL
	Reverse        *ReverseConfig
	SourceInsecure bool
	Logger         *log.Logger
	JavascriptURL  string
	Transport      http.RoundTripper
}

type ReverseConfig struct {
	Address        string
	Port           int
	CookieDomain   string
	InjectURLs     []string
	OnlyDomain     bool
	DumpURL        []string
	CookieHttpOnly bool
}
