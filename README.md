# go-wwpass

This is a Go server-side client library for [WWPass](https://www.wwpass.com/) authentication service, to be used with [wwpass-frontend](https://github.com/wwpass/wwpass-frontend).

## Installation

```bash
go get github.com/wwpass/go-wwpass@latest
```

## Usage

Full API documentation is available in [Go package documentation](https://pkg.go.dev/github.com/wwpass/go-wwpass?tab=doc).

Depending on your framework of choice or lack thereof, the application may differ, but the basic authentication cycle works like this:

### 1. Have the frontend ask the server for a ticket

```html
<div id="wwpass-qrcode" style="width: 200px !important;"></div>
<script type="text/javascript" src="/static/wwpass-frontend.js"></script>
<script type="text/javascript">
  WWPass.authInit({
    qrcode: document.querySelector('#wwpass-qrcode'), 
    ticketURL: '/login/wwpass-ticket',
    callbackURL: '/login/wwpass'
  });
</script>
```

where the handler for `/login/wwpass-ticket` calls `wwpass.GetTicket()` and responds with JSON:

```json
{ "ticket": "<ticket>", "ttl": <ttl> }
```

### 2. Handle the callback URL

As described in the
[wwpass-frontend](https://github.com/wwpass/wwpass-frontend) documentation,
`wwp_ticket` query string parameter will contain the authenticated ticket. Use
that in `wwpass.GetPUID()` to obtain the user's unique identifier.

Specific applications of the said unique identifier remain up to you.

## Support

If you have any questions, contact us at <support@wwpass.com>

## License

This program is licensed under the terms of [MIT License](LICENSE).

Copyright (c) 2025 WWPass Corporation.
