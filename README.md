# @digitalocean/webhook-sdk

## Getting Started

Install the package:

```
npm install @digitalocean/webhook-sdk
```

or

```
yarn add @digitalocean/webhook-sdk
```

### Verifying a payload signature

Use `Signature.parse` and `signature.verify` to verify an incoming webhook payload request.

**Important:** Make sure to pass the body of the request to `signature.verify` **raw** without formatting it to avoid slight mismatches and thus failures to verify the signature. By default, your HTTP server might parse the incoming JSON and provide an object in the body. The example below uses `express.raw` specifically to prevent that.

```js
const { Signature, HTTPHeaderSignature } = require('@digitalocean/webhook-sdk')
const express = require('express');
const { createServer } = require('http');

const app = express();
const server = createServer(app);

const SECRET = process.env.SIGNATURE_SECRET

app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const signatureHeader = req.headers[HTTPHeaderSignature];
    const signature = Signature.parse(signatureHeader);
    signature.verify(req.body, SECRET);
    res.status(200).send('verified');
  } catch (error) {
    return res.status(401).send(`failed to verify: ${error.message}`)
  }
});


server.listen(8080, function () {
  console.log('Listening on http://0.0.0.0:8080');
});

```

### Signing a payload using a secret

Use `Signature.createSignature` to sign a payload.

```js
app.post('/sign', express.raw({ type: 'application/json' }), (req, res) => {
  try {
    const signature = Signature.createSignature({
      payload: req.body,
      secrets: [SECRET],
      timestamp: Date.now()
    })
    return res.status(200).send(signature.toString())
  } catch (error) {
    return res.status(500).send(`failed to sign payload: ${error.message}`, )
  }
})

```

## Signature and Request Format

**Header**: `do-signature` <br />
**Format**: `t={ts},v1={sig}` <br />
- **ts**:  The current unix timestamp at the time the request is made. This may change across retries. <br />
- **v1**: Indicates the signature scheme version. Currently, only v1 is available.<br />
  
**Examples**: 
- one secret
  - `t=1492774577,v1=5257a869e7ecee108d8bd`
- two secrets
  - `t=1492774577,v1=5257a869e7ecee108d8bd,v1=cee108d8bd5257a869e7e`
- one secret, two scheme versions
  - `t=1492774577,v2=1fe71593b0c,v1=5257a869e7ecee108d8bd`
- two secrets, two scheme versions
  -  `t=1492774577,v2=1fe71593b0c,v2=3190e6d8151ac120,v1=5257a869e7ecee108d8bd,v1=cee108d8bd5257a869e7e`

## License

This package is licensed under the [Apache License 2.0](LICENSE).

Copyright 2023 DigitalOcean.