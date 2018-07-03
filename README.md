# Betaflight Boot Logo Replacer

This web app can create font files for the MAX7456 OSD chip with a customized boot logo image, which can be then uploaded to a compatible flight controller using the Betaflight Configurator. Requires Python 3.

## Installing

### Install requirements

Like always, just use `pip` to install dependencies on your system:

```bash
sudo pip3 install -r requirements.txt
```

Or even better, you may consider using a [virtual environment](https://docs.python.org/3/tutorial/venv.html).

### Download OSD fonts

Fonts from the Betaflight project are not part of this repo, but are required by this app. Run [`update-fonts.sh`](update-fonts.sh) to download them from Betaflight Configurator's repo.

### Enable reCAPTCHA

This web app supports [reCAPTCHA](https://www.google.com/recaptcha) to repell robots and keep them from spamming. Once you have created an account at the official reCAPTCHA home page and registered your site, you can provide the *site key* and *secret key* to the app to enable the reCAPTCHA widget. Copy [`recaptcha.cfg.sample`](recaptcha.cfg.sample) as `recaptcha.cfg` and edit the copied file to include the keys for your site. 

### Set up SSL

SSL is enabled by default, the required certificate (`app.crt`) and key (`app.key`) files can be created by running [`create-cert.sh`](create-cert.sh). The `--no-ssl` command line option can be used to disable this.

## Source image restrictions

The input image for the custom logo must satisfy these requirements:

* image has to be exactly 288px×72px
* the best to use PNG or BMP format
* background must be full green (#00ff00)
* must use white (#fff) and black (#000) colors only
* it's better to use RGB mode than RGBA (alpha is ignored anyway)
* green areas will be transparent on the OSD

## Command-line usage

```bash
usage: app.py [-h] [--no-ssl] [--no-recaptcha] [-p PORT] [-s ADDR] [-v] [-d]

optional arguments:
  -h, --help            show this help message and exit
  --no-ssl              disable SSL support (default: False)
  --no-recaptcha        disable reCAPTCHA (default: False)
  -p PORT, --port PORT  server port (default: 8720)
  -s ADDR, --host ADDR  host address (default: 0.0.0.0)
  -v                    verbosity level, can be used multiple times (default:
                        0)
  -d, --debug           enable debug mode and autoreload (default: False)
```
