package main

// This code is released under the MIT license by Mimmo Mane, 2025.
// THIS SOFTWARE IS PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND

import (
	"context"
	"errors"
	"fmt"
	"strings"
  "strconv"
  "path"
	"net"
	"net/http"
	"net/http/httputil"
	"golang.org/x/net/webdav"
	"io/fs"
  "os"
	"time"
  "runtime"
)

const (
  APP_TAG = "GoWebDAV-v0.1"

	ERROR   = 0
	WARNING = 1
	INFO    = 2
  DEBUG   = 3

	GDW_ENV_PREFIX  = "GWD_"
	ENV_VERBOSITY   = GDW_ENV_PREFIX + "VERBOSE"
	ENV_HOST        = GDW_ENV_PREFIX + "HOST"
	ENV_PORT        = GDW_ENV_PREFIX + "PORT"
	ENV_PATH        = GDW_ENV_PREFIX + "PATH"
	ENV_PREFIX      = GDW_ENV_PREFIX + "PREFIX"
	ENV_SERVE_MODE  = GDW_ENV_PREFIX + "SERVE_MODE"
	ENV_ZONE_HEADER = GDW_ENV_PREFIX + "ZONE_HEADER"

  MODE_FOLDER = "folder"
  MODE_ZONE   = "zone"
  MODE_BOTH   = "folder+zone"
)

type app struct {
	root_handler webdav.Handler
	zone_handler map[string]*webdav.Handler
	host         string
	port         uint16
  verbosity    uint16
  hide_root    bool
  zone_header  string
}

type logOpt struct {
	zero  bool
	skip  uint16
	level uint16
}

func (t*app) shouldLog(opt logOpt) bool { // TODO : remove ???
	if opt.level > t.verbosity {
		return false
	}
  return true
}

func (t*app) log(msgs ...interface{}) {
	opt := logOpt{}
	for _, m := range msgs {
		switch a := m.(type) {
		case logOpt:
			if a.skip != 0 {
				opt.skip = a.skip
			}
			if a.level != 0 {
				opt.level = a.level
			}
			if a.zero {
				opt = logOpt{}
			}
		}
	}
	if !t.shouldLog(opt) {
		return
	}
	sourcepos := "?:?"
	if _, b, c, d := runtime.Caller(1 + int(opt.skip)); d {
    i := strings.LastIndex(b, "/")
    if i > 0 {
      b = b[i+1:]
    }
		sourcepos = fmt.Sprintf("%v:%v", b, c)
	}
	severity := "DEBUG"
  switch opt.level {
    case ERROR: severity = "ERROR"
    case WARNING: severity = "WARNING"
    case DEBUG: severity = "DEBUG"
  }
	fmt.Printf("%s [%s %v]", severity, time.Now().Format(time.RFC3339), sourcepos)
	for _, v := range msgs {
		switch v.(type) {
		default:
			fmt.Printf(" %#v", v)
    case error:
			fmt.Printf(" %v", v)
    case string:
			fmt.Printf(" %v", v)
		case logOpt:
		}
	}
	fmt.Printf("\n")
}

func (t*app) logRequest(req *http.Request, err error) {
	sk := logOpt{skip: 1}
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return
	}
	requestDump, _ := httputil.DumpRequest(req, true)
	rd := string(requestDump)
	if errors.Is(err, webdav.ErrConfirmationFailed) ||
		errors.Is(err, webdav.ErrForbidden) ||
		errors.Is(err, webdav.ErrLocked) ||
		errors.Is(err, webdav.ErrNoSuchLock) {
		t.log(sk, logOpt{level: INFO}, "WebDAV request error", "error:", err, "request:", rd)
		return
	} else {
		t.log(sk, logOpt{level: ERROR}, "internal handler error", "error:", err, "request:", rd)
	}
}

func (t*app) Bind() (net.Listener, error) {
	t.root_handler.Logger = func(req *http.Request, err error) { t.logRequest(req, err) }

	addr := fmt.Sprintf("%s:%d", t.host, t.port)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
    t.log(logOpt{level:ERROR}, err)
		return nil, err
	}

	return ln, nil
}

func (t*app) SelectZoneHandler(r *http.Request) *webdav.Handler{
  zone := r.Header.Get(t.zone_header)
  var handler *webdav.Handler
  if t.hide_root || t.zone_handler != nil {
	  t.log(logOpt{level: DEBUG}, "using zone", "'" + zone + "'")
  }
  if !t.hide_root && zone == "" {
    handler = &t.root_handler
  }
  if t.zone_handler != nil && zone != "" {
    handler = t.zone_handler[zone]
  }
  if t.shouldLog(logOpt{level: DEBUG}) {
    requestDump, _ := httputil.DumpRequest(r, true)
    rd := string(requestDump)
    t.log(logOpt{level: DEBUG}, "got WebDav request: ", rd)
  }
  return handler
}

// writer that write an empty body.
type nothingWriter struct{ http.ResponseWriter }
func (w nothingWriter) Write(data []byte) (int, error) { return 0, nil }

func (t*app) WebDAVHandler(w http.ResponseWriter, r *http.Request) {

  handler := t.SelectZoneHandler(r)
  if handler == nil {
		t.log(logOpt{level: DEBUG}, "returning 404 Not Found for", r.URL.Path)
    w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "404 Not Found")
    return
  }

  // RFC4918 allows to GET over a collection to return anything the implementation
  // found useful. A common choice is to let it behave like PROPFIND. Also HEAD
  // on collaction behaves in the same way of PROPFIND.
  switch r.Method {
  case http.MethodHead:
  	w = nothingWriter{w}
    fallthrough
  case http.MethodGet:
  	file_stat, err := handler.FileSystem.Stat(context.TODO(), r.URL.Path)
  	if err == nil && file_stat.IsDir() {
  		r.Method = "PROPFIND"
  		if r.Header.Get("Depth") == "" {
  			r.Header.Add("Depth", "1")
  		}
  	}
  }

	handler.ServeHTTP(w, r)
}

func (t*app) Run(ln net.Listener) error {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    t.WebDAVHandler(w, r)
	})
	server := &http.Server{}

	err := server.Serve(ln)
	if err != nil {
		t.log(logOpt{level:ERROR}, err)
	} else {
		t.log(logOpt{level:INFO}, "done")
	}
	return err
}

// Main and Configuration

func getenv(name, def string) string {
	val := os.Getenv(name)
	if val == "" {
		return def
	}
	return val
}

type subLockSystem struct{
  parent webdav.LockSystem
  name string
}

func (t*subLockSystem) translateResourceName(res string) string{
  if t.name != "" {
    if strings.HasSuffix(t.name, "/"){
      res = t.name + res
    } else {
      res = t.name + "/" + res
    }
  }
  return res
}

func (t*subLockSystem) Create(now time.Time, details webdav.LockDetails) (token string, err error){
  details.Root = t.translateResourceName(details.Root)
  return t.parent.Create(now, details)
}

func (t*subLockSystem) Unlock(now time.Time, token string) error{
  return t.parent.Unlock(now,token)
}

func (t*subLockSystem) Refresh(now time.Time, token string, duration time.Duration) (webdav.LockDetails, error){
  return t.parent.Refresh(now, token, duration)
}

func (t*subLockSystem) Confirm(now time.Time, name0, name1 string, conditions ...webdav.Condition) (release func(), err error){
  // TODO : does condition.ETag needs to be translate too (somehow) ?
  if name0 != "" {
    name0 = t.translateResourceName(name0)
  }
  if name1 != "" {
    name1 = t.translateResourceName(name1)
  }
  return t.parent.Confirm(now, name0, name1, conditions...)
}

func (t*app) ZoneConfig(serve_path string) {
  if t.zone_handler == nil {
    t.zone_handler = map[string]*webdav.Handler{}
  }
  items, err := os.ReadDir(serve_path)
  if err != nil {
    t.log(logOpt{level:ERROR}, "can not access folder: ", serve_path)
    return
  }
  for _, item := range items {
      if item.IsDir() {
        name := item.Name()
        wh := t.root_handler // clone
        wh.LockSystem = &subLockSystem{t.root_handler.LockSystem, name}
	      wh.FileSystem = webdav.Dir(path.Join(serve_path, name))
        t.zone_handler[name] = &wh
      }
  }
}

func (t*app) ParseConfig() {

  t.root_handler.LockSystem = &subLockSystem{webdav.NewMemLS(), ""}

	verb, err := strconv.Atoi(getenv(ENV_VERBOSITY, "2"))
	if err != nil {
		t.log(logOpt{level: ERROR}, "Wrong value for variable "+ENV_VERBOSITY, err)
		return
	}
  t.verbosity = uint16(verb)

	t.host = getenv(ENV_HOST, "127.0.0.1")

	serve_path := getenv(ENV_PATH, "./")
	t.root_handler.FileSystem = webdav.Dir(path.Clean(serve_path))

	t.root_handler.Prefix = getenv(ENV_PREFIX, "")

	port, err := strconv.Atoi(getenv(ENV_PORT, "0"))
	if err != nil {
		t.log(logOpt{level: ERROR}, "Wrong value for variable "+ENV_PORT, err)
		return
	}
	t.port = uint16(port)

	t.zone_header = getenv(ENV_ZONE_HEADER, "Authorization")

	serve_mode := getenv(ENV_SERVE_MODE, MODE_FOLDER)
  switch serve_mode {
  default:
		t.log(logOpt{level: ERROR}, "Wrong value for variable "+ENV_SERVE_MODE)
		return
  case MODE_FOLDER: // nothing else to do
  case MODE_ZONE:
    t.ZoneConfig(serve_path)
    t.hide_root = true
  case MODE_BOTH:
    t.ZoneConfig(serve_path)
  }

	fmt.Printf("Serving mode: [%s]\n", serve_mode)
	fmt.Printf("Verbosity level: [%d]\n", t.verbosity)
	fmt.Printf("Serving content of: [%s]\n", serve_path)
	fmt.Printf("Removing prefix from requested URL: [%s]\n", t.root_handler.Prefix)
	fmt.Printf("Serving URL with prefix: [%s]\n", t.root_handler.Prefix)
	fmt.Printf("Serving content at host: [%s]\n", t.host)
	fmt.Printf("Trying configured port: [%d]\n", port)
  if t.zone_handler != nil {
    fmt.Printf("Zone header: [%s]\n", t.zone_header)
    for k := range(t.zone_handler){
      fmt.Printf("Serving zone: [%s]\n", k)
    }
  }
}

func (t*app) Main() {

	if len(os.Args) != 1 {
		print_help()
		return
	}
	fmt.Printf("%s - for help run: %s help\n", APP_TAG, os.Args[0])

	t.ParseConfig()

	ln, err := t.Bind()
	if err != nil || ln == nil {
		t.log("ERROR", "Server stopped due to previous errors.")
		return
	}

	addr := ln.Addr().String()
	part := strings.Split(addr, ":")
	host, port := addr, addr
	if part != nil && len(part) == 2 {
		host, port = part[0], part[1]
	}

	t.log(logOpt{level: INFO}, "Starting WebDAV server at http://"+host+":"+port)
	err = t.Run(ln)
	if err != nil {
		t.log(logOpt{level: ERROR}, err)
		t.log(logOpt{level: ERROR}, "Server stopped due to previous errors.")
	}
}

func main() {
  wd := &app{}
	wd.Main()
}

func print_help() { fmt.Printf("%s", APP_TAG+`

This is a simple WebDAV server.

Running it in a clean environment, without arguments, will serve the current
folder, in read and write mode, on localhost and a random port. The chosen
port, as well as any log, will be print in the standard console output.

It supports just WebDAV protocol over plain http. No TSL, no authantication, no
complex configuration.  It is meant to be placed behind a reverse proxy that
can provide all the advanced features. File access protection should be
provided at operating system and file system level.

However some behaviour can be configured with the following environment
variables (default values in square brakets).

- `+ENV_VERBOSITY+` [0]. It may be 0, 1, 2 or 3: greatest number means
  more information in the log.

- `+ENV_HOST+` [127.0.0.1]. The host to bind to.

- `+ENV_PORT+` [0]. The port to bind to.

- `+ENV_PATH+` [./]. The folder to serve content from. We call this
  'root folder'.

- `+ENV_PREFIX+` []. The prefix of the requested URL to be deleted before
  handling the request.

- `+ENV_SERVE_MODE+` [folder]. In the 'folder' mode a file will be served with
  the path obtained joining the root folder path and the URI in the request.
  The 'zone' will serve separately each sub-folder of the root folder, but on
  the same port. The sub-server is chosen looking at the 'Authorization' header
  in the request, that must be equal to the name of one of the sub-folder,
  oterwise a '404 Not Found' error is returned. In the 'folder+zone' mode the
  server behave like the 'zone' mode but it fallbacks to 'folder' mode when the
  'Authorization' header is empty.

- `+ENV_ZONE_HEADER+` [Authorization]. This is the name of the header of the http
  requesto to be used as the sub-folder name in the 'zone' mode.

The 'zone' serving mode is implemented to improve the interoperability with the
reverse proxies.

`)}

