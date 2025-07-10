
# Go Web-DAV

This is a minimal WebDAV server. In the [github release
page](https://github.com/pocomane/gowebdav/releases/latest) there are the pre-built
executables for linux, windows and mac.

The app simply exposes the WebDAV go package. No advanced webserver features are
handled (e.g. caching, auth, load balance, etc.) since it is meant to be used
behind a reverse proxy like nginx that will provide such functionality.

THIS SOFTWARE IS PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND. The code is
released under the MIT license while the used librearies are under the 3-Clause
BSD license. So you are free to use it for free or commercial projects,
sharing the modifications or not.

# Usage

Launching the app without arguments will serve the current folder on 127.0.0.1
and a random port. The chosen port as well as other log information is printed
on the standard console.

The configuration is done through environment variables. For more information
launch the app with the single command line argument 'help'.

# Client

The javascript client is in the `testclient.html` file. With the right
configuration it can be server from the WebDAV server itself.

# Example configuration

Consider the following configuration:

~~~
export GWD_HOST="127.0.0.1"
export GWD_PORT="8123"
export GWD_PATH="/opt/webdav"
export GWD_ZONE_ENABLE_ZONE="USER PUBLIC SCRIPT"

export GWD_ZONE_HEAD_USER="anuser:apwd"
export GWD_ZONE_FOLDER_USER="user"
export GWD_ZONE_PREFIX_USER="/priv"
export GWD_ZONE_AUTH_USER="basicauth"

export GWD_ZONE_HEAD_PUBLIC=""
export GWD_ZONE_FOLDER_PUBLIC="/public"
export GWD_ZONE_PREFIX_PUBLIC="/pub"
export GWD_ZONE_CGI_PUBLIC="/pub/cgi.sh"

./gowebdav
~~~

It will launch the server at 127.0.0.1, on port 8123, serving

- `/opt/webdav/public` at `http://127.0.0.1:8123/pub` with no login required
- `/opt/webdav/user` at `http://127.0.0.1:8123/priv` with username "anuser" and
  password "apwd"
- The filese `/opt/webdav/public/cgi.sh` will be threated in in a CGI-like mode

If you put the `testclient.html` client under `/opt/webdav/public` you can
access the UI at `http://127.0.0.1:8123/pub/testclient.html`. It will
automatically show you the public content or you can use it to insert the user
credentials.

Note that the server lets anyone to modify the content of the public folder,
`testclient.html` included. If you want avoid it, you have to restrict the
acces at the OS level, i.e. making the `/opt/webdav/public` folder read-only
for the user that will run `.\gowebdav`.

If you want to serve over `https` instead, you have just to provide the key and
certificate files. Supposing that they are in `/opt/webdav/cert.pem` and
`/opt/webdav/key.pem`, you just need to add the following variables:

~~~
export GWD_TLS_CERTIFICATE="/opt/webdav/cert.pem"
export GWD_TLS_KEY="/opt/webdav/key.pem"
~~~

