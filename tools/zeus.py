import execjs, os, json, time, threading, traceback

from flask import Flask, request
from werkzeug.serving import ThreadedWSGIServer
from selenium.webdriver.support.ui import WebDriverWait
from selenium import webdriver

app = Flask(__name__)

options = webdriver.ChromeOptions()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-extensions")
options.add_argument("--disable-gpu")
options.add_argument("--disable-dev-shm-usage")


def deepai_refresh():
    while True:
        driver = webdriver.Chrome(options=options)
        try:
            driver.get("https://deepai.org")
            wait = WebDriverWait(driver, 15)
            cookies = driver.get_cookies()
            print(cookies)
        except Exception as e:
            traceback.print_exc()
        driver.quit()
        time.sleep(600)


# curl -X POST -d '{}' -H "Content-Type: application/json" http://127.0.0.1:8860/gptforlove
@app.route("/gptforlove", methods=["POST"])
def get_gptforlove_secret():
    dir = os.path.dirname(__file__)
    dir += "/npm/node_modules/crypto-js"
    source = """
CryptoJS = require('{dir}/crypto-js')
var k = '14487141bvirvvG'
    , e = Math.floor(new Date().getTime() / 1e3);
var t = CryptoJS.enc.Utf8.parse(e)
    , o = CryptoJS.AES.encrypt(t, k, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
});
return o.toString()
"""
    source = source.replace("{dir}", dir)
    dict = {"secret": execjs.compile(source).call("")}
    return json.dumps(dict)


if __name__ == "__main__":
    thread = threading.Thread(target=deepai_refresh)
    thread.start()
    port = os.getenv("PORT", "8860")
    ip = os.getenv("IP", "0.0.0.0")
    print(f"start zeus at {ip}:{port}")
    server = ThreadedWSGIServer(ip, port, app)
    server.serve_forever()
