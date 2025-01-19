
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

