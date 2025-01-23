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
  ENV_BASIC_AUTH  = GDW_ENV_PREFIX + "CONVERT_TO_BASIC_AUTH"

  MODE_DEFAULT = ":."
  MODE_DIRECT = "direct"
  MODE_AUTO   = "auto"
)

type app struct {
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
  addr := fmt.Sprintf("%s:%s", t.host, t.port)

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
  sub_folder := t.zone_map[zone]
  t.log(logOpt{level: DEBUG}, "serving sub-folder", "'" + sub_folder + "'")
  handler = t.zone_handler[zone]
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

    // NOTE: this is done for any values of ENV_BASIC_AUTH since also without
    // such option the provided zone key may be compatible with the Basic Auth scheme
    w.Header().Set("WWW-Authenticate", `Basic realm="AUTH-REALM"`)

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

func getenv_bool(name string, def bool) (bool, error) {
  value := strings.ToLower(getenv(name, ""))
  if value == "" {
    return def, nil
  }
  switch value {
  default: return false, fmt.Errorf("wrong value for variable " + ENV_CLEAN_DEST)
  case "no": case "yes": case "0": case "1": case "false": case "true":
  }
  return (value == "yes" || value == "true" || value == "1"), nil
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

func (t*app) ZoneConfig(serve_path string, prefix string, serve_mode string, make_basic_auth bool) error {

  logger := func(req *http.Request, err error) { t.logRequest(req, err) }
  base_lock_system := webdav.NewMemLS()

  t.zone_map = map[string]string{}

  if serve_mode != MODE_AUTO {

    serve_list := strings.Split(serve_mode, ";")
    for k := 0; k < len(serve_list); k += 1{
      serve_record := strings.Split(serve_list[k], ":")
      if len(serve_record) != 2 {
        err := fmt.Errorf("invalid zone configuration - got %d fields in the zone record '%s' instead of 2", len(serve_record), serve_list[k])
        t.log(logOpt{level:ERROR}, err)
        return err
      }
      t.zone_map[serve_record[1]] = path.Clean(serve_record[0])
    }

  } else {

    items, err := os.ReadDir(serve_path)
    if err != nil {
      err := fmt.Errorf("can not access folder '%s' - %s", serve_path, err)
      t.log(logOpt{level:ERROR}, err)
      return err
    }
    for _, item := range items {
      if item.IsDir() {
        name := item.Name()
        t.zone_map[name] = name
      }
    }

  }

  if make_basic_auth {
    ba_zone_map := map[string]string{}
    for k, v := range t.zone_map {
      if !strings.Contains(k, ":") {
        k = k + ":" + k
      }
      key := "Basic " + base64.StdEncoding.EncodeToString([]byte(k))
      ba_zone_map[key] = v
    }
    t.zone_map = ba_zone_map
  }

  t.zone_handler = map[string]*webdav.Handler{}
  for k, v := range t.zone_map {
    if t.zone_handler[k] == nil {
      wh := webdav.Handler{}
      wh.Logger = logger
      wh.LockSystem = &subLockSystem{base_lock_system, v}
      wh.FileSystem = webdav.Dir(path.Join(serve_path, v))
      wh.Prefix = prefix
      t.zone_handler[k] = &wh
    }
  }
  return nil
}

func (t*app) ParseConfig() error {
  verb, err := strconv.Atoi(getenv(ENV_VERBOSITY, "2"))
  if err != nil {
    err := fmt.Errorf("wrong value for variable '%s' - %s", ENV_VERBOSITY, err)
    t.log(logOpt{level: ERROR}, err)
    return err
  }
  t.verbosity = uint16(verb)

  t.host = getenv(ENV_HOST, "127.0.0.1")

  t.port = getenv(ENV_PORT, "0")
  _, err = strconv.Atoi(t.port)
  if err != nil {
    err := fmt.Errorf("wrong value for variable '%s' - %s", ENV_PORT, err)
    t.log(logOpt{level: ERROR}, err)
    return err
  }

  t.zone_header = getenv(ENV_ZONE_HEADER, "Authorization")

  translate_to_basic_auth, err := getenv_bool(ENV_BASIC_AUTH, false)
  if err != nil {
    t.log(logOpt{level: ERROR}, err)
    return err
  }

  serve_path := getenv(ENV_PATH, "./")
  prefix := getenv(ENV_PREFIX, "")
  serve_mode := getenv(ENV_SERVE_MODE, MODE_DEFAULT)
  err = t.ZoneConfig(serve_path, prefix, serve_mode, translate_to_basic_auth)
  if err != nil {
    err := fmt.Errorf("error during zone configuration")
    t.log(logOpt{level: ERROR}, err)
    return err
  }

  clean_dest, err := getenv_bool(ENV_CLEAN_DEST, false)
  if err != nil {
    t.log(logOpt{level: ERROR}, err)
    return err
  }
  t.clean_dest = clean_dest

  t.tls_cert = strings.ToLower(getenv(ENV_TLS_CERT, ""))
  t.tls_key = strings.ToLower(getenv(ENV_TLS_KEY, ""))
  if (t.tls_cert == "" && t.tls_key != "") || (t.tls_cert != "" && t.tls_key == "") {
    err := fmt.Errorf("the '%s' and '%s' variables must be set togheter or be unset both", ENV_TLS_CERT, ENV_TLS_KEY)
    t.log(logOpt{level: ERROR}, err)
    return err
  }
  if t.tls_key != "" {
    f, err := os.Open(t.tls_key)
    if err != nil {
      err := fmt.Errorf("can not read '%s' key file", t.tls_key)
      t.log(logOpt{level:ERROR}, err)
      return err
    }
    f.Close()
    f, err = os.Open(t.tls_cert)
    if err != nil {
      err := fmt.Errorf("can not read '%s' cert file", t.tls_cert)
      t.log(logOpt{level:ERROR}, err)
      return err
    }
    f.Close()
  }

  fmt.Printf("You can connect to the WebDAVServer %s\n", t.ConnectionString())
  fmt.Printf("Sub-folder discovery: [%v]\n", serve_mode == MODE_AUTO)
  fmt.Printf("Verbosity level: [%d]\n", t.verbosity)
  fmt.Printf("Serving content of: [%s]\n", serve_path)
  fmt.Printf("Removing prefix from requested URL: [%s]\n", prefix)
  fmt.Printf("Serving URL with prefix: [%s]\n", prefix)
  fmt.Printf("Serving content at host: [%s]\n", t.host)
  fmt.Printf("Trying configured port: [%s]\n", t.port)
  fmt.Printf("Clean destination in copy request: [%v]\n", clean_dest)
  fmt.Printf("Translate zone map to Basic Auth format: [%v]\n", translate_to_basic_auth)
  fmt.Printf("Zone header: [%s]\n", t.zone_header)
  for _, v := range(t.zone_map){
    fmt.Printf("Serving zone in sub-folder: [%s]\n", v)
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
encryption or authentication required. The chosen port, as well as any log,
will be print in the standard console output.

It supports just WebDAV protocol over http or https, basic authantication, no
caching or other complex feature. It is meant to be placed behind a
reverse proxy that can provide all the advanced behaviour. File access
protection should be provided at operating system and file system level.

However the following environment variables can customize some behaviour of the
server (default values in square brakets).

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

- `+ENV_SERVE_MODE+` [`+MODE_DEFAULT+`].  This is a list of sub-folder of the
  path in `+ENV_PATH+` to be served.  The format is
  'folder1:content1;folder2:content2' and so on. It will serve the sub-folder
  'folder1' when the 'Authorization' header contains exactly 'content1' and so
  on. The '.' can be used as folder to represent the `+ENV_PATH+` itself. The
  empty string can be used as content to allow empty or missing 'Authorization'
  header. Instead of the map you can set the variable to '`+MODE_AUTO+`': it
  will create a map with 'content' equal to each folder name (useful for
  reverse proxy integration). This is useful for reverese proxy
  interoperability, but it can be made more standard setting the
  '`+ENV_BASIC_AUTH+`' variables.

- '`+ENV_BASIC_AUTH+`' [no]. This will transform all the accepted values for
  the 'Authorization' header to something that respect the Basic Auth scheme. If
  the original content does contain a colon, the part before it will be used as
  username while the part after as password. If it does not contain any colon,
  it will be threated both as username and password.
`)}

