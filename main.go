package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/url"
	"os"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// persistentJar wraps an fhttp.CookieJar to add file persistence.
type persistentJar struct {
	mu          sync.Mutex
	jar         http.CookieJar
	filename    string
	urls        map[string]*url.URL // Track URLs to serialize cookies
	fullCookies map[string][]*http.Cookie
}

type cookieEntry struct {
	Name       string    `json:"name"`
	Value      string    `json:"value"`
	Path       string    `json:"path"`
	Domain     string    `json:"domain"`
	Expires    time.Time `json:"expires"`
	RawExpires string    `json:"rawExpires"`
	MaxAge     int       `json:"maxAge"`
	Secure     bool      `json:"secure"`
	HttpOnly   bool      `json:"httpOnly"`
	SameSite   int       `json:"sameSite"`
	Raw        string    `json:"raw"`
	Unparsed   []string  `json:"unparsed"`
}

type jarData struct {
	Cookies map[string][]*cookieEntry `json:"cookies"`
}

// newPersistentJar creates a new persistent CookieJar.
func newPersistentJar(filename string) (*persistentJar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	p := &persistentJar{
		jar:         jar,
		filename:    filename,
		urls:        make(map[string]*url.URL),
		fullCookies: make(map[string][]*http.Cookie),
	}

	if err := p.load(); err != nil {
		if os.IsNotExist(err) {
			// Create the file if it doesn't exist.
			if createErr := p.save(); createErr != nil {
				log.Printf("Warning: failed to create initial session file %s: %v", filename, createErr)
			}
		} else {
			log.Printf("Warning: failed to load session from %s: %v", filename, err)
		}
	}

	return p, nil
}

// SetCookies implements the http.CookieJar interface.
func (p *persistentJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	p.mu.Lock()
	p.urls[u.Host] = u
	// Overwrite/update full cookies using the raw input to preserve metadata.
	// Since we only receive the new cookies here, we should actually merge them.
	// But `SetCookies` is meant to be called by the client when updating.
	// To keep it simple, we store all seen cookies for this host.
	existing := p.fullCookies[u.Host]

	// Create a map to deduplicate by name, domain, path
	type cookieKey struct {
		Name, Domain, Path string
	}
	cookieMap := make(map[cookieKey]*http.Cookie)
	for _, c := range existing {
		cookieMap[cookieKey{c.Name, c.Domain, c.Path}] = c
	}
	for _, c := range cookies {
		cookieMap[cookieKey{c.Name, c.Domain, c.Path}] = c
	}
	var merged []*http.Cookie
	for _, c := range cookieMap {
		merged = append(merged, c)
	}
	p.fullCookies[u.Host] = merged
	p.mu.Unlock()

	p.jar.SetCookies(u, cookies)
	if err := p.save(); err != nil {
		log.Printf("Warning: failed to save session to %s: %v", p.filename, err)
	}
}

// Cookies implements the http.CookieJar interface.
func (p *persistentJar) Cookies(u *url.URL) []*http.Cookie {
	p.mu.Lock()
	p.urls[u.Host] = u
	p.mu.Unlock()

	return p.jar.Cookies(u)
}

func (p *persistentJar) load() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	data, err := os.ReadFile(p.filename)
	if err != nil {
		return err
	}

	var jd jarData
	if err := json.Unmarshal(data, &jd); err != nil {
		return err
	}

	for rawURL, entries := range jd.Cookies {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		p.urls[u.Host] = u

		var cookies []*http.Cookie
		for _, e := range entries {
			cookies = append(cookies, &http.Cookie{
				Name:       e.Name,
				Value:      e.Value,
				Path:       e.Path,
				Domain:     e.Domain,
				Expires:    e.Expires,
				RawExpires: e.RawExpires,
				MaxAge:     e.MaxAge,
				Secure:     e.Secure,
				HttpOnly:   e.HttpOnly,
				SameSite:   http.SameSite(e.SameSite),
				Raw:        e.Raw,
				Unparsed:   e.Unparsed,
			})
		}
		p.fullCookies[u.Host] = cookies
		p.jar.SetCookies(u, cookies)
	}

	return nil
}

func (p *persistentJar) save() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	jd := jarData{
		Cookies: make(map[string][]*cookieEntry),
	}

	for _, u := range p.urls {
		cookies := p.fullCookies[u.Host]
		if len(cookies) == 0 {
			continue
		}

		var entries []*cookieEntry
		for _, c := range cookies {
			entries = append(entries, &cookieEntry{
				Name:       c.Name,
				Value:      c.Value,
				Path:       c.Path,
				Domain:     c.Domain,
				Expires:    c.Expires,
				RawExpires: c.RawExpires,
				MaxAge:     c.MaxAge,
				Secure:     c.Secure,
				HttpOnly:   c.HttpOnly,
				SameSite:   int(c.SameSite),
				Raw:        c.Raw,
				Unparsed:   c.Unparsed,
			})
		}

		// To save generically for the domain, we construct a generic URL.
		genericURL := fmt.Sprintf("https://%s", u.Host)
		jd.Cookies[genericURL] = entries
	}

	data, err := json.MarshalIndent(jd, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(p.filename, data, 0644)
}

func getRandomProfile() profiles.ClientProfile {
	availableProfiles := []profiles.ClientProfile{
		profiles.Chrome_120,
		profiles.Chrome_117,
		profiles.Chrome_112,
		profiles.Chrome_111,
		profiles.Chrome_110,
		profiles.Chrome_109,
		profiles.Safari_15_6_1,
		profiles.Safari_16_0,
		profiles.Safari_Ipad_15_6,
		profiles.Safari_IOS_15_5,
		profiles.Safari_IOS_15_6,
		profiles.Safari_IOS_16_0,
		profiles.Firefox_117,
		profiles.Firefox_120,
		profiles.Opera_89,
		profiles.Opera_90,
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(availableProfiles))))
	if err != nil {
		// Fallback to Chrome 120 if random generation fails
		return profiles.Chrome_120
	}

	return availableProfiles[n.Int64()]
}

func main() {
	var targetURL string
	var referer string
	var byteRange string
	var sessionID string

	flag.StringVar(&targetURL, "url", "", "Target URL (required)")
	flag.StringVar(&referer, "ref", "", "Referer header value (optional)")
	flag.StringVar(&byteRange, "range", "", "Byte range for the Range header (optional, e.g., '0-1024')")
	flag.StringVar(&sessionID, "session", "", "A string identifier for the session (optional)")

	flag.Parse()

	if targetURL == "" {
		fmt.Fprintf(os.Stderr, "Error: -url flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	_, err := url.ParseRequestURI(targetURL)
	if err != nil {
		log.Fatalf("Invalid URL provided: %v", err)
	}

	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(getRandomProfile()),
	}

	if sessionID != "" {
		sessionFile := fmt.Sprintf("session_%s.json", sessionID)
		jar, err := newPersistentJar(sessionFile)
		if err != nil {
			log.Fatalf("Failed to initialize session jar: %v", err)
		}
		options = append(options, tls_client.WithCookieJar(jar))
	} else {
		jar, err := cookiejar.New(nil)
		if err != nil {
			log.Fatalf("Failed to create in-memory cookie jar: %v", err)
		}
		options = append(options, tls_client.WithCookieJar(jar))
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		log.Fatalf("Failed to create TLS client: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	if referer != "" {
		req.Header.Set("Referer", referer)
	}

	if byteRange != "" {
		req.Header.Set("Range", fmt.Sprintf("bytes=%s", byteRange))
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Discard the body to minimize memory/I/O usage
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		log.Printf("Warning: failed to read response body fully: %v", err)
	}

	fmt.Printf("Request successful. Status code: %d\n", resp.StatusCode)
}
