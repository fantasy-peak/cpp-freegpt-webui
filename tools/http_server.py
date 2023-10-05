# python3 -m venv venv
# source venv/bin/activate

# apt install dbus-x11/lunar
# export $(dbus-launch)

# apt install flatpak
# flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
# flatpak install flathub com.google.Chrome -y
# curl -X POST -d '{"domain": "https://deepai.org"}' -H "Content-Type: application/json" http://127.0.0.1:8000

import json
import threading
import time
import traceback

from flask import Flask, request
from werkzeug.serving import ThreadedWSGIServer
from selenium.webdriver.support.ui import WebDriverWait
from selenium import webdriver

app = Flask(__name__)

domains = ["https://deepai.org"]
cookie_local_cache = {}
lock = threading.Lock()

options = webdriver.ChromeOptions()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-extensions")
options.add_argument("--disable-gpu")
options.add_argument("--disable-dev-shm-usage")
driver = webdriver.Chrome(options=options)


def poll():
    while True:
        print("Polling...")
        for domain in domains:
            try:
                driver.get(domain)
                wait = WebDriverWait(driver, 15)
                cookies = driver.get_cookies()
                json_str = json.dumps(cookies)
                print(json_str)
                lock.acquire()
                cookie_local_cache[domain] = json_str
                lock.release()
            except Exception as e:
                traceback.print_exc()
        time.sleep(600)


@app.route("/", methods=["POST"])
def get_cookie():
    body = request.get_json()
    print("http request body:", str(body))
    cookie_str = "{}"
    lock.acquire()
    if body["domain"] in cookie_local_cache:
        cookie_str = cookie_local_cache[body["domain"]]
    lock.release()
    return cookie_str


if __name__ == "__main__":
    thread = threading.Thread(target=poll)
    thread.start()
    server = ThreadedWSGIServer("localhost", 8000, app)
    server.serve_forever()
