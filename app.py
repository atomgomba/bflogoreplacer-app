#!/usr/bin/env python3
import os
import sys
import logging as log
from configparser import ConfigParser, SectionProxy
import json
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from tempfile import mkstemp
from time import time
from uuid import uuid4
from typing import Optional

from bflogoreplacer import replace_logo
from bflogoreplacer.common import McmError
from tornado.ioloop import IOLoop
from tornado.routing import URLSpec
from tornado.web import Application, RequestHandler, StaticFileHandler
from tornado.httpclient import AsyncHTTPClient
from tornado.httpserver import HTTPServer

LOG_LEVELS = [log.ERROR, log.WARNING, log.INFO, log.DEBUG]
STATIC_DIR = "static"
TEMPLATES_DIR = "templates"
FONTS_DIR = STATIC_DIR + "/fonts"
SSL_OPTIONS = {
    "certfile": "app.crt",
    "keyfile": "app.key",
}
RECAPTCHA_CFG_FILE = "recaptcha.cfg"
RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
RECAPTCHA_RESPONSE_PARAM = "g-recaptcha-response"
DEFAULT_FONT_NAME = "default"


# noinspection PyAbstractClass
class MainHandler(RequestHandler):
    def __init__(self, application, request, **kwargs):
        super().__init__(application, request, **kwargs)
        self._httpclient = None

    def get(self):
        self._render_page()

    async def post(self):
        if self.is_recaptcha_enabled:
            response = self.get_body_argument(RECAPTCHA_RESPONSE_PARAM)
            verified = await self._verify_recaptcha(response)
            if not verified:
                self.send_error(401)
                return
        fonts = self.settings["fonts"]
        font_key = self.get_body_argument("font", DEFAULT_FONT_NAME)
        try:
            if font_key not in fonts:
                raise FormIncompleteError("Incorrect font selected")
            font_path = fonts.get(font_key)
            if "srcimg" not in self.request.files:
                raise FormIncompleteError("Missing image file")
            srcimg = self.request.files["srcimg"][0]
            _, ext = os.path.splitext(srcimg["filename"])
            fp, image_path = mkstemp(suffix=ext)
            with open(fp, "wb") as f:
                f.write(srcimg["body"])
            log.debug("uploaded file: " + image_path)
            output = replace_logo(font_path, image_path)
        except IOError:
            self._render_page("Cannot read file")
            return
        except KeyError as e:
            self._render_page(str(e))
            return
        except McmError as e:
            self._render_page(str(e))
            return
        else:
            self.set_header("Content-Type", "application/octet-stream")
            outfilename = "custom-%s-%d.mcm" % (font_key, round(time()))
            self.set_header("Content-Disposition", 'attachment; filename="%s"' % outfilename)
            self.write(output)

    def _render_page(self, error: Optional[str] = None):
        params = dict(font_names=self.settings["font_names"],
                      error=error,
                      selected_font=self.get_body_argument("font", DEFAULT_FONT_NAME),
                      recaptcha=self.settings["recaptcha"])
        if error is not None:
            self.set_status(400)
        self.render("index.html", **params)

    @property
    def remoteip(self) -> str:
        x_real_ip = self.request.headers.get("X-Real-IP")
        return x_real_ip or self.request.remote_ip

    @property
    def is_recaptcha_enabled(self) -> bool:
        return bool(self.settings["recaptcha"])

    async def _verify_recaptcha(self, code: str) -> bool:
        if self._httpclient is None:
            self._httpclient = AsyncHTTPClient()
        secretkey = self.settings["recaptcha"]["secretkey"]
        body = "secret=%s&response=%s&remoteip=%s" % (secretkey, code, self.remoteip)
        response = await self._httpclient.fetch(RECAPTCHA_VERIFY_URL, method="POST", body=body)
        data = json.loads(response.body.decode())
        success = data.get("success", False)
        log.debug("recatpcha: %s: %s" % (code, success))
        return success


class FormIncompleteError(KeyError):
    def __init__(self, *args):
        super().__init__(*args)
        self.message = args[0] if 0 < len(args) else None

    def __str__(self):
        return self.message or ""


def _collect_fonts() -> dict:
    fonts = {}
    for path in os.listdir(FONTS_DIR):
        name = os.path.basename(path).replace(".mcm", "")
        fonts[name] = os.path.abspath(os.path.join(FONTS_DIR, path))
    if fonts:
        log.debug("found fonts: %s" % ", ".join(list(fonts.keys())))
    return fonts


def _load_recaptcha_settings() -> Optional[SectionProxy]:
    if not (os.path.exists(RECAPTCHA_CFG_FILE) and os.path.isfile(RECAPTCHA_CFG_FILE)):
        log.debug("config file not found: %s" % RECAPTCHA_CFG_FILE)
        return None
    cp = ConfigParser()
    cp.read(RECAPTCHA_CFG_FILE)
    try:
        return cp['recaptcha']
    except KeyError:
        log.debug("[recaptcha] section not found in config file")
        return None


def main(args):
    log.basicConfig(format='%(asctime)s %(levelname)s: %(message)s')
    if args.verbosity >= len(LOG_LEVELS):
        log.error("Verbosity must be 0 <= n < %d" % len(LOG_LEVELS))
        return 1
    log.getLogger().setLevel(LOG_LEVELS[args.verbosity])
    fonts = _collect_fonts()
    if not fonts:
        log.error("no font files found; did you forget to run update-fonts.sh?")
        return 1
    recaptcha_settings = _load_recaptcha_settings() if not args.no_recaptcha else False
    if not recaptcha_settings:
        logfun = log.warning if recaptcha_settings is None else log.info
        logfun("reCAPTCHA is disabled")
    cookie_secret = str(uuid4())
    app_settings = {
        "autoreload": args.debug,
        "debug": args.debug,
        "template_path": TEMPLATES_DIR,
        "fonts": fonts,
        "font_names": sorted(fonts.keys()),
        "recaptcha": recaptcha_settings,
        "static_path": STATIC_DIR,
        "cookie_secret": cookie_secret,
        "xsrf_cookies": True,
    }
    routes = [URLSpec(r"/?", MainHandler), ]
    if args.debug:
        log.debug("debug mode enabled")
        routes.append(URLSpec(r"/%s/(.*)" % STATIC_DIR, StaticFileHandler))
    server_settings = {}
    if not args.no_ssl:
        server_settings["ssl_options"] = SSL_OPTIONS
    else:
        log.info("SSL is disabled")
    http_server = HTTPServer(Application(routes, **app_settings), **server_settings)
    http_server.listen(args.port, args.host)
    log.info("listening on %s:%d..." % (args.host, args.port))
    try:
        IOLoop.instance().start()
    except KeyboardInterrupt:
        log.info("interrupted by user; bye!")
    return 0


if __name__ == "__main__":
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("--no-ssl", action="store_true", help="disable SSL support")
    parser.add_argument("--no-recaptcha", action="store_true", help="disable reCAPTCHA")
    parser.add_argument("-p", "--port", type=int, default=8720, help="server port")
    parser.add_argument("-s", "--host", metavar="ADDR", type=str, default="0.0.0.0", help="host address")
    parser.add_argument("-v", dest="verbosity", action="count", default=0,
                        help="verbosity level, can be used multiple times")
    parser.add_argument("-d", "--debug", action="store_true", help="enable debug mode and autoreload")
    sys.exit(main(parser.parse_args()))
