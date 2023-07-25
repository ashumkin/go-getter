package getter

// these tests are almost the copy of get_http_test
// with HttpGetter replaced with ConfigServerGetter

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-cleanhttp"
)

func TestConfigServerGetter_impl(t *testing.T) {
	var _ Getter = NewConfigServerGetter()
}

func TestConfigServerGetter_none(t *testing.T) {
	ln := testHttpServer(t)
	defer ln.Close()

	g := NewConfigServerGetter()
	dst := tempDir(t)
	defer os.RemoveAll(dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/none"

	// Get it!
	if err := g.Get(dst, &u); err == nil {
		t.Fatal("should error")
	}
}

func TestConfigServerGetter_file(t *testing.T) {
	ln := testHttpServer(t)
	defer ln.Close()

	g := NewConfigServerGetter()
	dst := tempTestFile(t)
	defer os.RemoveAll(filepath.Dir(dst))

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/file"

	// Get it!
	if err := g.GetFile(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("err: %s", err)
	}
	assertContents(t, dst, "Hello\n")
}

func TestConfigServerGetter_auth(t *testing.T) {
	ln := testHttpServer(t)
	defer ln.Close()

	g := NewConfigServerGetter()
	dst := tempDir(t)
	defer os.RemoveAll(dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/meta-auth"
	u.User = url.UserPassword("foo", "bar")

	// But, using a wrapper client with a file getter will work.
	c := &Client{
		Getters: map[string]Getter{
			"http": g,
			"file": new(FileGetter),
		},
		Src:  u.String(),
		Dst:  dst,
		Mode: ClientModeDir,
	}

	err := c.Get()

	if err != nil {
		t.Fatalf("err: %s", err)
	}
}

// verify that the default httpClient no longer comes from http.DefaultClient
func TestConfigServerGetter_cleanhttp(t *testing.T) {
	ln := testHttpServer(t)
	defer ln.Close()

	// break the default http client
	http.DefaultClient.Transport = errRoundTripper{}
	defer func() {
		http.DefaultClient.Transport = http.DefaultTransport
	}()

	g := NewConfigServerGetter()
	dst := tempDir(t)
	defer os.RemoveAll(dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/header"

	// But, using a wrapper client with a file getter will work.
	c := &Client{
		Getters: map[string]Getter{
			"http": g,
			"file": new(FileGetter),
		},
		Src:  u.String(),
		Dst:  dst,
		Mode: ClientModeDir,
	}

	err := c.Get()

	if err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestConfigServerGetter__RespectsContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	ln := testHttpServer(t)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/file"
	dst := tempDir(t)

	rt := hookableHTTPRoundTripper{
		before: func(req *http.Request) {
			err := req.Context().Err()
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Expected http.Request with canceled.Context, got: %v", err)
			}
		},
		RoundTripper: http.DefaultTransport,
	}

	g := NewConfigServerGetter()
	g.SetClient(&Client{
		Ctx: ctx,
	})
	g.httpGetter.Client = &http.Client{
		Transport: &rt,
	}

	err := g.Get(dst, &u)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func TestConfigServerGetter__XTerraformGetDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln := testHttpServerWithXTerraformGetLoop(t)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/loop"
	dst := tempDir(t)

	g := NewConfigServerGetter()
	g.SetClient(&Client{
		Ctx: ctx,
	})
	g.httpGetter.Client = &http.Client{}

	err := g.Get(dst, &u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// test a source url with no protocol
func TestConfigServerGetter__XTerraformGetDetected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln := testHttpServerWithXTerraformGetDetected(t)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/first"
	dst := tempDir(t)

	c := &Client{
		Ctx:  ctx,
		Src:  u.String(),
		Dst:  dst,
		Mode: ClientModeDir,
		Options: []ClientOption{
			func(c *Client) error {
				c.Detectors = append(c.Detectors, testCustomDetector{})
				return nil
			},
		},
	}

	err := c.Get()
	if err != nil {
		t.Fatal(err)
	}
}

func TestConfigServerGetter__XTerraformGetProxyBypass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln := testHttpServerWithXTerraformGetProxyBypass(t)

	proxyLn := testHttpServerProxy(t, ln.Addr().String())

	t.Logf("starting malicious server on: %v", ln.Addr().String())
	t.Logf("starting proxy on: %v", proxyLn.Addr().String())

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/start"
	dst := tempDir(t)

	proxy, err := url.Parse(fmt.Sprintf("http://%s/", proxyLn.Addr().String()))
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}

	transport := cleanhttp.DefaultTransport()
	transport.Proxy = http.ProxyURL(proxy)

	configServerGetter := NewConfigServerGetter()
	configServerGetter.httpGetter.Client = &http.Client{
		Transport: transport,
	}

	client := &Client{
		Ctx: ctx,
		Getters: map[string]Getter{
			"http": configServerGetter,
		},
	}

	client.Src = u.String()
	client.Dst = dst

	err = client.Get()
	if err != nil {
		t.Logf("client get error: %v", err)
	}
}

func TestConfigServerGetter__XTerraformGetConfiguredGettersBypass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln := testHttpServerWithXTerraformGetConfiguredGettersBypass(t)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/start"
	dst := tempDir(t)

	rt := hookableHTTPRoundTripper{
		before: func(req *http.Request) {
			t.Logf("making request")
		},
		RoundTripper: http.DefaultTransport,
	}

	configServerGetter := NewConfigServerGetter()
	configServerGetter.httpGetter.Client = &http.Client{
		Transport: &rt,
	}

	client := &Client{
		Ctx:  ctx,
		Mode: ClientModeDir,
		Getters: map[string]Getter{
			"http": configServerGetter,
		},
	}

	t.Logf("%v", u.String())

	client.Src = u.String()
	client.Dst = dst

	err := client.Get()
	if err != nil {
		if !strings.Contains(err.Error(), "no getter available for X-Terraform-Get source protocol") {
			t.Fatalf("expected no getter available for X-Terraform-Get source protocol, got: %v", err)
		}
	}
}

func TestConfigServerGetter__endless_body(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln := testHttpServerWithEndlessBody(t)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/"
	dst := tempDir(t)

	configServerGetter := NewConfigServerGetter()
	configServerGetter.httpGetter.MaxBytes = 10
	configServerGetter.httpGetter.DoNotCheckHeadFirst = true

	client := &Client{
		Ctx:  ctx,
		Mode: ClientModeFile,
		Getters: map[string]Getter{
			"http": configServerGetter,
		},
	}

	t.Logf("%v", u.String())

	client.Src = u.String()
	client.Dst = dst

	err := client.Get()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigServerGetter_subdirLink(t *testing.T) {
	ln := testHttpServerSubDir(t)
	defer ln.Close()

	configServerGetter := NewConfigServerGetter()
	dst, err := ioutil.TempDir("", "tf")
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	t.Logf("dst: %q", dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/regular-subdir//meta-subdir"

	t.Logf("url: %q", u.String())

	client := &Client{
		Src:  u.String(),
		Dst:  dst,
		Mode: ClientModeAny,
		Getters: map[string]Getter{
			"http": configServerGetter,
		},
	}

	err = client.Get()
	if err != nil {
		t.Fatalf("get err: %v", err)
	}
}

func TestConfigServerGetter_yaml(t *testing.T) {
	ln := testHttpServer(t)
	defer ln.Close()

	g := NewConfigServerGetter()
	dst := tempTestFile(t)
	defer os.RemoveAll(filepath.Dir(dst))

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/yaml"

	// Get it!
	if err := g.GetFile(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("err: %s", err)
	}
	assertContents(t, dst, "yaml:\n  key1: value1\n  key2: value2\n  key3:\n    subkey3_1: subvalue3_1\n    subkey3_2: subvalue3_2\n")
}

func TestConfigServerGetter_unsupported_format(t *testing.T) {
	ln := testHttpServer(t)
	defer ln.Close()

	g := NewConfigServerGetter()
	dst := tempTestFile(t)
	defer os.RemoveAll(filepath.Dir(dst))

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/yaml"
	u.RawQuery = "xpath=yaml&format=json"

	// Get it!
	if err := g.GetFile(dst, &u); err != nil {
		if !strings.Contains(err.Error(), "unsupported format json") {
			t.Fatalf("expected 'unsupported format json' error, but was %v", err)
		}
		return
	}
	t.Fatalf("There must be the 'unsupported' format error")
}

func TestConfigServerGetter_yaml_root_key(t *testing.T) {
	ln := testHttpServer(t)
	defer ln.Close()

	g := NewConfigServerGetter()
	dst := tempTestFile(t)
	defer os.RemoveAll(filepath.Dir(dst))

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/yaml"
	u.RawQuery = "xpath=yaml"

	// Get it!
	if err := g.GetFile(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("err: %s", err)
	}
	assertContents(t, dst, "key1: value1\nkey2: value2\nkey3:\n  subkey3_1: subvalue3_1\n  subkey3_2: subvalue3_2\n")
}

func TestConfigServerGetter_yaml_key1(t *testing.T) {
	ln := testHttpServer(t)
	defer ln.Close()

	g := NewConfigServerGetter()
	dst := tempTestFile(t)
	defer os.RemoveAll(filepath.Dir(dst))

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/yaml"
	u.RawQuery = "xpath=yaml.key1"

	// Get it!
	if err := g.GetFile(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("err: %s", err)
	}
	assertContents(t, dst, "value1\n")
}

func TestConfigServerGetter_yaml_absent_xpath(t *testing.T) {
	ln := testHttpServer(t)
	defer ln.Close()

	g := NewConfigServerGetter()
	dst := tempTestFile(t)
	defer os.RemoveAll(filepath.Dir(dst))

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/yaml"
	u.RawQuery = "xpath=key1"

	// Get it!
	if err := g.GetFile(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("err: %s", err)
	}
	assertContents(t, dst, "")
}

func TestConfigServerGetter_yaml_newkey(t *testing.T) {
	ln := testHttpServer(t)
	defer ln.Close()

	g := NewConfigServerGetter()
	dst := tempTestFile(t)
	defer os.RemoveAll(filepath.Dir(dst))

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/yaml"
	u.RawQuery = "xpath=yaml.key3&newkey=prefix"

	// Get it!
	if err := g.GetFile(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("err: %s", err)
	}
	assertContents(t, dst, "prefix:\n  subkey3_1: subvalue3_1\n  subkey3_2: subvalue3_2\n")
}
