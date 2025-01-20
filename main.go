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
  "encoding/base64"
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
  ENV_CLEAN_DEST  = GDW_ENV_PREFIX + "CLEAN_DESTINATION"
  ENV_TLS_CERT    = GDW_ENV_PREFIX + "TLS_CERTIFICATE"
  ENV_TLS_KEY     = GDW_ENV_PREFIX + "TLS_KEY"
  ENV_ZONE_HEADER = GDW_ENV_PREFIX + "ZONE_HEADER"
  ENV_SERVE_MODE  = GDW_ENV_PREFIX + "SERVE_MODE"

  MODE_ROOT   = "root"
  MODE_DIRECT = "direct"
  MODE_AUTO   = "auto"
)

type app struct {
  root_handler webdav.Handler
  zone_handler map[string]*webdav.Handler
  host         string
  port         string
  verbosity    uint16
  zone_header  string
  clean_dest   bool
  tls_cert     string
  tls_key      string
  zone_map     map[string]string
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

  addr := fmt.Sprintf("%s:%s", t.host, t.port)

  ln, err := net.Listen("tcp", addr)
  if err != nil {
    t.log(logOpt{level:ERROR}, err)
    return nil, err
  }

  return ln, nil
}

func (t*app) SelectZoneHandler(r *http.Request) *webdav.Handler{
  zone_request := r.Header.Get(t.zone_header)
  var zone string
  if t.zone_map != nil {
    zone = t.zone_map[zone_request]
  } else {
    zone = zone_request
  }
  var handler *webdav.Handler
  if t.zone_handler == nil && zone == "" {
    t.log(logOpt{level: DEBUG}, "using root zone")
    handler = &t.root_handler
  }
  if t.zone_handler != nil && zone != "" {
    t.log(logOpt{level: DEBUG}, "using zone", "'" + zone + "'")
    handler = t.zone_handler[zone]
  }
  if t.shouldLog(logOpt{level: DEBUG}) {
    requestDump, _ := httputil.DumpRequest(r, true)
    rd := string(requestDump)
    t.log(logOpt{level: DEBUG}, "got WebDav request: ", rd)
  }
  return handler
}

func (t*app) ConnectionString() string {
  if t.tls_key == "" {
    return fmt.Sprintf("http://%s:%s", t.host, t.port)
  } else {
    return fmt.Sprintf("https://%s:%s", t.host, t.port)
  }
}

// writer that write an empty body.
type nothingWriter struct{ http.ResponseWriter }
func (w nothingWriter) Write(data []byte) (int, error) { return 0, nil }

func (t*app) WebDAVHandler(w http.ResponseWriter, r *http.Request) {

  handler := t.SelectZoneHandler(r)
  if handler == nil {
    t.log(logOpt{level: DEBUG}, "returning 401 Unauthorized", r.URL.Path)
    if t.zone_handler != nil { // TODO : find a more meaningful condition ?
      w.Header().Set("WWW-Authenticate", `Basic realm="AUTH-REALM"`)
    }
    w.WriteHeader(http.StatusUnauthorized)
    fmt.Fprintf(w, "401 Unauthorized")
    return
  }

  switch r.Method {
  case "MOVE": fallthrough
  case "COPY":
    if t.clean_dest {
      dest := r.Header.Get("Destination")
      new_dest := dest
      if new_dest == dest { new_dest = strings.TrimPrefix(dest, "http://") }
      if new_dest == dest { new_dest = strings.TrimPrefix(dest, "https://") }
      if new_dest != dest { // if a prefix was found
        i := strings.Index(new_dest, "/")
        if i < 0 {
          new_dest = t.ConnectionString() + "/"
        } else {
          new_dest = t.ConnectionString() + new_dest[i:]
        }
        r.Header.Set("Destination", new_dest)
        t.log(logOpt{level:DEBUG}, "changed destination from", dest, "to", new_dest)
      }
    }

  case http.MethodHead:
    w = nothingWriter{w}
    fallthrough
  // RFC4918 allows to GET over a collection to return anything the implementation
  // found useful. A common choice is to let it behave like PROPFIND. Also HEAD
  // on collaction behaves in the same way of PROPFIND.
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

  var err error
  if t.tls_key == "" {
    err = server.Serve(ln)
  } else {
    err = server.ServeTLS(ln, t.tls_cert, t.tls_key)
  }

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

func (t*app) ZoneConfig(serve_path string, prefix string, serve_mode string) error {

  if serve_mode != MODE_ROOT && serve_mode != MODE_DIRECT && serve_mode != MODE_AUTO {
    t.log(logOpt{level: ERROR}, "wrong value for variable "+ENV_SERVE_MODE)
    return fmt.Errorf("invalid serving mode")
  }

  t.root_handler.LockSystem = &subLockSystem{webdav.NewMemLS(), ""}
  t.root_handler.FileSystem = webdav.Dir(path.Clean(serve_path))
  t.root_handler.Prefix = prefix

  if serve_mode == MODE_ROOT {
    return nil
  }

  t.zone_handler = map[string]*webdav.Handler{}
  items, err := os.ReadDir(serve_path)
  if err != nil {
    t.log(logOpt{level:ERROR}, "can not access folder: ", serve_path, err)
    return err
  }
  t.zone_map = map[string]string{}
  for _, item := range items {
    if item.IsDir() {
        name := item.Name()

        key := name
        switch serve_mode {
        case MODE_DIRECT:
          key = name
        case MODE_AUTO:
          key = "Basic " + base64.StdEncoding.EncodeToString([]byte(name+":"+name))
        }

        t.zone_map[key] = name
    }
  }
  for _, name := range t.zone_map {
    if t.zone_handler[name] == nil {
      wh := t.root_handler // clone
      wh.LockSystem = &subLockSystem{t.root_handler.LockSystem, name}
      wh.FileSystem = webdav.Dir(path.Join(serve_path, name))
      t.zone_handler[name] = &wh
    }
  }
  return nil
}

func (t*app) ParseConfig() error {
  config_error := fmt.Errorf("%s", "wrong configuration")

  verb, err := strconv.Atoi(getenv(ENV_VERBOSITY, "2"))
  if err != nil {
    t.log(logOpt{level: ERROR}, "Wrong value for variable "+ENV_VERBOSITY, err)
    return err
  }
  t.verbosity = uint16(verb)

  t.host = getenv(ENV_HOST, "127.0.0.1")

  t.port = getenv(ENV_PORT, "0")
  _, err = strconv.Atoi(t.port)
  if err != nil {
    t.log(logOpt{level: ERROR}, "Wrong value for variable "+ENV_PORT, err)
    return config_error
  }

  t.zone_header = getenv(ENV_ZONE_HEADER, "Authorization")

  serve_path := getenv(ENV_PATH, "./")
  prefix := getenv(ENV_PREFIX, "")
  serve_mode := getenv(ENV_SERVE_MODE, MODE_ROOT)
  err = t.ZoneConfig(serve_path, prefix, serve_mode)
  if err != nil {
    t.log(logOpt{level: ERROR}, "error during zone configuration", err)
    return config_error
  }

  clean_dest := strings.ToLower(getenv(ENV_CLEAN_DEST, "no"))
  if clean_dest != "no" && clean_dest != "yes" {
    t.log(logOpt{level: ERROR}, "Wrong value for variable "+ENV_CLEAN_DEST)
    return config_error
  }
  t.clean_dest = (clean_dest == "yes")

  t.tls_cert = strings.ToLower(getenv(ENV_TLS_CERT, ""))
  t.tls_key = strings.ToLower(getenv(ENV_TLS_KEY, ""))
  if (t.tls_cert == "" && t.tls_key != "") || (t.tls_cert != "" && t.tls_key == "") {
    t.log(logOpt{level: ERROR}, "the following variables must be set togheter or be unset both: "+ENV_TLS_CERT+", "+ENV_TLS_KEY)
    return config_error
  }
  if t.tls_key != "" {
    f, err := os.Open(t.tls_cert)
    if err != nil {
      t.log(logOpt{level:ERROR}, "can not read '"+t.tls_cert+"'")
      return config_error
    }
    f.Close()
    f, err = os.Open(t.tls_cert)
    if err != nil {
      t.log(logOpt{level:ERROR}, "can not read '"+t.tls_cert+"'")
      return config_error
    }
    f.Close()
  }

  fmt.Printf("Serving mode: [%s]\n", serve_mode)
  fmt.Printf("Verbosity level: [%d]\n", t.verbosity)
  fmt.Printf("Serving content of: [%s]\n", serve_path)
  fmt.Printf("Removing prefix from requested URL: [%s]\n", t.root_handler.Prefix)
  fmt.Printf("Serving URL with prefix: [%s]\n", t.root_handler.Prefix)
  fmt.Printf("Serving content at host: [%s]\n", t.host)
  fmt.Printf("Trying configured port: [%s]\n", t.port)
  fmt.Printf("Clean destination in copy request: [%s]\n", clean_dest)
  if t.zone_handler != nil {
    fmt.Printf("Zone header: [%s]\n", t.zone_header)
    for k := range(t.zone_handler){
      fmt.Printf("Serving zone: [%s]\n", k)
    }
  }

  return nil
}

func (t*app) Main() {

  if len(os.Args) != 1 {
    print_help()
    return
  }
  fmt.Printf("%s - for help run: %s help\n", APP_TAG, os.Args[0])

  err := t.ParseConfig()
  if err != nil {
    t.log(logOpt{level:ERROR}, "Server stopped due to previous errors.")
    return
  }

  ln, err := t.Bind()
  if err != nil || ln == nil {
    t.log(logOpt{level:ERROR}, "Server stopped due to previous errors.")
    return
  }

  addr := ln.Addr().String()
  part := strings.Split(addr, ":")
  if part != nil && len(part) == 2 {
    t.port = part[1]
  }

  t.log(logOpt{level: INFO}, "Starting WebDAV server at", t.ConnectionString())
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
folder, in read and write mode, on localhost and a random port, without
encryption. The chosen port, as well as any log, will be print in the standard
console output.

It supports just WebDAV protocol over http or https. No authantication, caching
or complex configuration.  It is meant to be placed behind a reverse proxy that
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

- `+ENV_CLEAN_DEST+` [No]. It forces the COPY and MOVE requests to ignore the
  scheme, host, and port parts of the 'Destination' header.  This is useful if
  there is a reverse proxy that does not properly transform such header.

- `+ENV_TLS_CERT+` []. Path to the TLS certificate file. It enables serving
  encrypted https instead of http. A key must be provided with
  `+ENV_TLS_KEY+`.

- `+ENV_TLS_KEY+` []. Path to the TLS certificate file. It enables serving
  encrypted https instead of http. A certificate must be provided with
  `+ENV_TLS_CERT+`.

- `+ENV_ZONE_HEADER+` [Authorization]. This is the name of the header of the http
  requests to be used as the sub-folder name in the 'zone' mode.

- `+ENV_SERVE_MODE+` [`+MODE_ROOT+`]. In the '`+MODE_ROOT+`' mode a file will
  be served with the path obtained joining the root folder path and the URI in
  the request.  The '`+MODE_DIRECT+`' mode  will serve separately each sub-folder
  of the root folder, but on the same port. The content of the 'Authorization'
  header must match one of the sub-folder, otherwise an 'Unauthorized' error is
  returned. The '`+MODE_DIRECT+`' mode can be used to improve the
  interoperability with the reverse proxies.  The '`+MODE_DIRECT+`' mode is
  similar to '`+MODE_DIRECT+`', but the 'Authorization' header must contain a
  username and a password in the Basic Auth format and equal to the name of the
  folder that have to be access.

`)}

