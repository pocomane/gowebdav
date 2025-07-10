package main

// This code is released under the MIT license by Mimmo Mane, 2025.
// THIS SOFTWARE IS PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND

import (
  "context"
  "errors"
  "fmt"
  "strings"
  "strconv"
  "path/filepath"
  "encoding/base64"
  "net"
  "net/http"
  "net/http/httputil"
  "golang.org/x/net/webdav"
  "io"
  "io/fs"
  "os"
  "os/exec"
  "time"
  "runtime"
)

const (
  APP_TAG = "GoWebDAV-v0.3-rc"

  ERROR   = 0
  WARNING = 1
  INFO    = 2
  DEBUG   = 3

  GDW_ENV_PREFIX  = "GWD_"

  ENV_VERBOSITY   = GDW_ENV_PREFIX + "VERBOSE"
  ENV_HOST        = GDW_ENV_PREFIX + "HOST"
  ENV_PORT        = GDW_ENV_PREFIX + "PORT"
  ENV_PATH        = GDW_ENV_PREFIX + "PATH"
  ENV_CLEAN_DEST  = GDW_ENV_PREFIX + "CLEAN_DESTINATION"
  ENV_TLS_CERT    = GDW_ENV_PREFIX + "TLS_CERTIFICATE"
  ENV_TLS_KEY     = GDW_ENV_PREFIX + "TLS_KEY"
  ENV_ZONE_HEADER = GDW_ENV_PREFIX + "ZONE_HEADER"

  ENV_ZONE_LIST   = GDW_ENV_PREFIX + "ZONE_ENABLE_ZONE"
  ENV_HEAD_ZONE   = GDW_ENV_PREFIX + "ZONE_HEAD_"
  ENV_FOLDER_ZONE = GDW_ENV_PREFIX + "ZONE_FOLDER_"
  ENV_PREFIX_ZONE = GDW_ENV_PREFIX + "ZONE_PREFIX_"
  ENV_AUTH_ZONE   = GDW_ENV_PREFIX + "ZONE_AUTH_"
  ENV_CGI_ZONE    = GDW_ENV_PREFIX + "ZONE_CGI_"

  AUTH_DEFAULT   = "basicauth"
  AUTH_DIRECT    = "direct"
  AUTH_BASICAUTH = "basicauth"

  AUTH_HEADER_DEFAULT = "Authorization"
)

const(
  INVALID_ZONE = iota
  WEBDAV_ZONE
)

type Zone struct {
  Type      int
  Webdav    *webdav.Handler
  Subfolder string
  Cgi       map[string]bool
}

type app struct {
  zone         map[string]Zone
  host         string
  port         string
  verbosity    uint16
  serve_path   string
  zone_header  string
  clean_dest   bool
  tls_cert     string
  tls_key      string
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
    case INFO: severity = "INFO"
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

func (t*app) SelectZone(r *http.Request) Zone {
  zone_header := r.Header.Get(t.zone_header)
  var handler *webdav.Handler
  sub_folder := t.zone[zone_header].Subfolder
  t.log(logOpt{level: DEBUG}, "serving zone in sub-folder", "'" + sub_folder + "'")
  zone := t.zone[zone_header]
  handler = zone.Webdav
  rd := ""
  if t.shouldLog(logOpt{level: DEBUG}) {
    rdb, _ := httputil.DumpRequest(r, true)
    rd = string(rdb)
  }
  t.log(logOpt{level: DEBUG}, "got WebDav request:", rd)
  if handler == nil {
    zone.Type = INVALID_ZONE
    t.log(logOpt{level: DEBUG}, "can not find zone for the request")
  } else {
    if strings.HasPrefix(r.URL.Path, handler.Prefix) {
      t.log(logOpt{level: DEBUG}, "handling path", r.URL.Path, "with prefix", "'" + handler.Prefix + "'")
    } else {
      t.log(logOpt{level: DEBUG}, "refusing path", r.URL.Path, "because it does not start with", "'" + handler.Prefix + "'")
      // WebDAV go library returns 404 Not Found for path not beginning with
      // the selected prefix. We override this behaviour to return 401
      // Unauthorized. This is needed to mix Public and Private zones on the
      // same server, using different prefixes.
      zone.Type = INVALID_ZONE
    }
  }
  return zone
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

func (t nothingWriter) Write(data []byte) (int, error) { return 0, nil }

func (t *app) CgiHandler(folder string, cgi string, w http.ResponseWriter, r *http.Request) {
  cmd_path := filepath.Join(t.serve_path, folder, cgi)
  cmd := exec.Command(cmd_path)
  piperead, pipewrite := io.Pipe()
  cmd.Stdin = piperead
  cmd.Stdout = w
  t.log(logOpt{level: DEBUG}, "running "+cmd_path)
  cmd.Stderr = os.Stderr
  err := cmd.Start()
  if err != nil {
    t.log(logOpt{level: ERROR}, err)
    return
  }
  r.Write(pipewrite)
  pipewrite.Close()
  err = cmd.Wait()
  if err != nil {
    t.log(logOpt{level: ERROR}, err)
    return
  }
}

func (t*app) WebDAVHandler(handler *webdav.Handler, w http.ResponseWriter, r *http.Request) {
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

func (t*app) RestHandler(w http.ResponseWriter, r *http.Request) {
  zone := t.SelectZone(r)
  if zone.Type == INVALID_ZONE {
    t.log(logOpt{level: DEBUG}, "returning 401 Unauthorized", r.URL.Path)

    // NOTE: this is done also for zone without AUTH_BASICAUTH since also the
    // provided zone key may be compatible with the Basic Auth scheme
    w.Header().Set("WWW-Authenticate", `Basic realm="AUTH-REALM"`)

    w.WriteHeader(http.StatusUnauthorized)
    fmt.Fprintf(w, "401 Unauthorized")
    return
  }
  url := r.URL.String()
  if zone.Cgi[url] {
    t.CgiHandler(zone.Subfolder, url, w, r)
    return
  }
  t.WebDAVHandler(zone.Webdav, w, r)
}

func (t *app) Run(ln net.Listener) error {

  http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    t.RestHandler(w, r)
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

func (t*app) AddZone(
  zone_name string,
  auth_head string,
  subfolder string,
  urlprefix string,
  auth_mode string,
  cgi_list  []string,
) error {

  if t.zone == nil {
    t.zone = map[string]Zone{}
  }
  var logger func(req *http.Request, err error)
  var base_lock_system webdav.LockSystem
  for _, zone := range t.zone {
    base_lock_system = zone.Webdav.LockSystem
    logger = zone.Webdav.Logger
    break
  }
  if base_lock_system == nil {
    base_lock_system = webdav.NewMemLS()
  }
  if logger == nil {
    logger = func(req *http.Request, err error) { t.logRequest(req, err) }
  }

  if auth_mode == AUTH_BASICAUTH {
    if auth_head != "" {
      if !strings.Contains(auth_head, ":") {
        auth_head = auth_head + ":" + auth_head
      }
      auth_head = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth_head))
    }
  }

  fullpath := filepath.Join(t.serve_path, subfolder)
  webdav_handler := webdav.Handler{
    Logger:     logger,
    FileSystem: webdav.Dir(fullpath),
    LockSystem: &subLockSystem{base_lock_system, subfolder},
    Prefix:     urlprefix,
  }

  cgi := map[string]bool{}
  for _, cgipath := range cgi_list {
    cgi[cgipath] = true
  }

  t.zone[auth_head] = Zone{
    Type:      WEBDAV_ZONE,
    Webdav:    &webdav_handler,
    Subfolder: subfolder,
    Cgi:       cgi,
  }
  t.log(logOpt{level: DEBUG}, "added zone at", fullpath, "with prefix", "'"+urlprefix+"'")

  return nil
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

func getenv_list(name string, separator string, def string) []string {
  list := getenv(name, "")
  if list == "" {
    return []string{}
  }
  return strings.Split(list, separator)
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

  t.zone_header = getenv(ENV_ZONE_HEADER, AUTH_HEADER_DEFAULT)
  t.serve_path = getenv(ENV_PATH, "./")

  zone_list := getenv_list(ENV_ZONE_LIST, " ", "ROOT")
  for _, zone_name := range zone_list {
    t.AddZone(
      zone_name,
      getenv(ENV_HEAD_ZONE + zone_name, ""),
      getenv(ENV_FOLDER_ZONE + zone_name, "."),
      getenv(ENV_PREFIX_ZONE + zone_name, ""),
      getenv(ENV_AUTH_ZONE + zone_name, AUTH_BASICAUTH),
      getenv_list(ENV_CGI_ZONE + zone_name, ",", ""),
    )
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

  if t.tls_cert == "" || t.tls_key == "" {
    fmt.Printf("!!! ATTENTION !!! Server is running without encryption. THIS IS VERY INSECURE.\n")
    fmt.Printf("Please set the %s and %s variables to enable encryption.\n", ENV_TLS_CERT, ENV_TLS_KEY)
    fmt.Printf("You can connect to the WebDAVServer %s\n", t.ConnectionString())
  } else {
    fmt.Printf("You can connect to the WebDAVServer %s\n", t.ConnectionString())
    fmt.Printf("Encription enabled: true\n")
    fmt.Printf("Encription key: %s\n", t.tls_key)
    fmt.Printf("Certificate: %s\n", t.tls_cert)
  }
  //fmt.Printf("Sub-folder discovery: [%v]\n", serve_mode == AUTH_AUTO)
  fmt.Printf("Verbosity level: [%d]\n", t.verbosity)
  fmt.Printf("Serving content at host: [%s]\n", t.host)
  fmt.Printf("Trying configured port: [%s]\n", t.port)
  fmt.Printf("Serving content in path: [%s]\n", t.serve_path)
  fmt.Printf("Clean destination in copy request: [%v]\n", clean_dest)
  // TODO : print if the zone header was translated to basic auth ?
  fmt.Printf("Zone selection header: [%s]\n", t.zone_header)
  fmt.Printf("End of general configuration section\n")
  for k, v := range t.zone {
    prefix := ""
    zh := v.Webdav
    if zh != nil {
      prefix = zh.Prefix
    }
    if prefix == "" {
      prefix = "/"
    }
    authentication := " with authentication enabled"
    if k == "" {
      authentication = " WITH AUTHENTICATION DISABLED"
    }
    fmt.Printf("Serving files from sub-folder [%s] under the endpoint [%s]%s\n", v.Subfolder, prefix, authentication)
    for url := range v.Cgi {
      fmt.Printf("URL [%s] will be searched in sub-folder [%s] and threated as CGI\n", url, v.Subfolder)
    }
    fmt.Printf("End of Zone configuration section\n")
  }
  if t.tls_cert == "" || t.tls_key == "" {
    fmt.Printf("!!! ATTENTION !!! Server is running without encryption. THIS IS VERY INSECURE.\n")
    fmt.Printf("Please set the %s and %s variables to enable encryption.\n", ENV_TLS_CERT, ENV_TLS_KEY)
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

- `+ENV_CLEAN_DEST+` [No]. It forces the COPY and MOVE requests to ignore the
  scheme, host, and port parts of the 'Destination' header.  This is useful if
  there is a reverse proxy that does not properly transform such header.

- `+ENV_TLS_CERT+` []. Path to the TLS certificate file. It enables serving
  encrypted https instead of http. A key must be provided with
  `+ENV_TLS_KEY+`.

- `+ENV_TLS_KEY+` []. Path to the TLS certificate file. It enables serving
  encrypted https instead of http. A certificate must be provided with
  `+ENV_TLS_CERT+`.

- `+ENV_ZONE_HEADER+` [`+AUTH_HEADER_DEFAULT+`]. This is the name of the header of the http
  requests to be used as the sub-folder name in the 'zone' mode.

 - `+ENV_ZONE_LIST+` [ROOT] - A whitespace separated list of "Zone" names. A
  zone define how to serve a folder and are configured through a set of dynamic
  named variables that ends with one of the zone names.

 - `+ENV_HEAD_ZONE+`X [] (X must be in `+ENV_ZONE_LIST+`) - The zone will be
  served when the `+AUTH_HEADER_DEFAULT+` header is equal to the string in this
  variable.

 - `+ENV_FOLDER_ZONE+`X [] (X must be in `+ENV_ZONE_LIST+`) - The subfolder
  of the path in the '`+ENV_PATH+`' variable that contains the files to be
  served for the zone.

 - `+ENV_PREFIX_ZONE+`X [] (X must be in `+ENV_ZONE_LIST+`) - This specify a
  prefix of the zone to be deleted from the requested URL before handling the
  request. If the requested URL does not start with the such prefix a 401
  Unauthorized error is returned.  Each prefix must begin with '/'.

 - `+ENV_AUTH_ZONE+`X [`+AUTH_DEFAULT+`] (X must be in `+ENV_ZONE_LIST+`) - When the
  mode is "`+AUTH_DIRECT+`", the content of `+ENV_HEAD_ZONE+`X must exactly match
  the `+AUTH_HEADER_DEFAULT+` header of the request. If the mode is "`+AUTH_BASICAUTH+`"
  the value in `+ENV_HEAD_ZONE+`X  is pre-parsed to make it compatible with
  the basic auth scheme

- `+ENV_CGI_ZONE+`X [] (X must be in `+ENV_ZONE_LIST+`) - A comma separated list of
  URLs. Instead of serve them as regular file, it is run in a new process.
  The request will be passed to its stdin while its stdout will be served.

`)
}
