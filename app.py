#!/usr/bin/env python3
import logging as log
log.basicConfig(format='%(asctime)s %(levelname)s: %(message)s')
import os
from configparser import ConfigParser
import json
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from tempfile import mkstemp
from time import time
from typing import Optional

from bflogoreplacer import replace_logo, DataLengthError, ImageSizeError, MissingHeaderError
from tornado.ioloop import IOLoop
from tornado.routing import URLSpec
from tornado.web import Application, RequestHandler, StaticFileHandler
from tornado.httpclient import AsyncHTTPClient
from tornado.httpserver import HTTPServer

LOG_LEVELS = [log.ERROR, log.WARNING, log.INFO, log.DEBUG]
STATIC_DIR = "static"
FONTS_DIR = STATIC_DIR + "/fonts"
RECAPTCHA_CFG_FILE = "recaptcha.cfg"
RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
RECAPTCHA_RESPONSE_PARAM = "g-recaptcha-response"


class MainHandler(RequestHandler):
    def __init__(self, application, request, **kwargs):
        super().__init__(application, request, **kwargs)
        self._httpclient = None

    def get(self):
        self._render_page()

    async def post(self):
        if self.use_recaptcha:
            response = self.get_body_argument(RECAPTCHA_RESPONSE_PARAM)
            verified = await self._verify_recaptcha(response)
            if not verified:
                self.send_error(401)
                return
        fonts = self.settings["fonts"]
        font_key = self.get_body_argument("font", "default")
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
            log.debug("tempfile: " + image_path)
            output = replace_logo(font_path, image_path)
        except IOError:
            self._render_page("Cannot read file")
            return
        except KeyError as e:
            self._render_page(str(e))
            return
        except ImageSizeError as e:
            self._render_page(str(e))
            return
        except DataLengthError as e:
            self._render_page(str(e))
            return
        except MissingHeaderError as e:
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
                      selected_font=self.get_body_argument("font", "default"),
                      recaptcha=self.settings["recaptcha"])
        if error is not None:
            self.set_status(400)
        self.render("index.html", **params)

    @property
    def remoteip(self) -> str:
        x_real_ip = self.request.headers.get("X-Real-IP")
        return x_real_ip or self.request.remote_ip

    @property
    def use_recaptcha(self) -> bool:
        return self.settings["recaptcha"] is not None

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
    def __init__(self, *args: object) -> None:
        super().__init__(*args)
        self.message = args[0] if 0 < len(args) else None

    def __str__(self):
        return self.message or ""


def _collect_fonts() -> dict:
    fonts = {}
    for path in os.listdir(FONTS_DIR):
        name = os.path.basename(path).replace(".mcm", "")
        fonts[name] = os.path.abspath(os.path.join(FONTS_DIR, path))
    return fonts


def _load_recaptcha_settings() -> ConfigParser or None:
    if not (os.path.exists(RECAPTCHA_CFG_FILE) and os.path.isfile(RECAPTCHA_CFG_FILE)):
        return None
    cp = ConfigParser()
    cp.read(RECAPTCHA_CFG_FILE)
    return cp['recaptcha']


def main(args):
    if args.verbosity >= len(LOG_LEVELS):
        raise IndexError("Verbosity must be 0 <= n < {}".format(len(LOG_LEVELS)))
    log.getLogger().setLevel(LOG_LEVELS[args.verbosity])
    fonts = _collect_fonts()
    routes = [URLSpec(r"/?", MainHandler), ]
    app_settings = {
        "autoreload": args.debug,
        "debug": args.debug,
        "template_path": "templates",
        "fonts": fonts,
        "font_names": sorted(fonts.keys()),
        "recaptcha": _load_recaptcha_settings(),
        "static_path": STATIC_DIR,
    }
    if args.debug:
        log.debug("in debug mode")
        routes.append(URLSpec(r"/%s/(.*)" % STATIC_DIR, StaticFileHandler))
    server_settings = {}
    if not args.no_ssl:
        server_settings["ssl_options"] = {
            "certfile": "app.crt",
            "keyfile": "app.key",
        }
    http_server = HTTPServer(Application(routes, **app_settings), **server_settings)
    http_server.listen(args.port, args.host)
    log.info("listening on {host}:{port}...".format(host=args.host, port=args.port))
    IOLoop.instance().start()


if __name__ == "__main__":
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("--no-ssl", action="store_true", help="disable SSL support")
    parser.add_argument("-p", "--port", type=int, default=8720, help="server port")
    parser.add_argument("-s", "--host", metavar="ADDR", type=str, default="0.0.0.0", help="host address")
    parser.add_argument("-v", dest="verbosity", action="count", default=0,
                        help="verbosity level, can be used multiple times")
    parser.add_argument("-d", "--debug", action="store_true", help="enable debug mode and autoreload")
    main(parser.parse_args())
