# History Proxy

Indexes the text of all web pages you visit so you can search your history.

## Installation

```
# (definitely set up a virtualenv for this, first)

pip install -r requirements.txt
```

## Running

```
python history.py
```

## Browser configuration

Once it's running, visit http://127.0.0.1:8000/cert (in FF; probably different for other browsers). Trust the CA certificate.

Set your browser's HTTP proxy to `127.0.0.1:8080`.

To see your history: http://127.0.0.1:8000/

To search: http://127.0.0.1:8000/search?q=bleepbloop
