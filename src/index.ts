import express, { ErrorRequestHandler } from 'express';
import session from 'express-session';
import crypto from 'crypto';
import { Issuer, TokenSet, generators } from 'openid-client';

declare module 'express-session' {
  export interface SessionData {
    tokenSet: TokenSet;
    state: string;
    codeVerifier: string;
    nonce: string;
    originalUrl: string;
    authorized: boolean;
  }
}

const app: express.Express = express()
const PORT = 3000

const issuer = new Issuer({
  issuer: 'https://<ISSUER>',
  authorization_endpoint: 'https://<ISSUER>/<AUTHORIZATION-ENDPOINT>',
  token_endpoint: 'https://<ISSUER>/<TOKEN-ENDPOINT>'
})

const client = new issuer.Client({
  client_id: '<YOUR-CLIENT-ID>',
  client_secret: '<YOUR-CLIENT-SECRET>',
  redirect_uris: ['http://localhost:3000/cb']
})

const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  res.status(err.status || 500).json({ err: { message: err.message } });
};


app.use(session({
  name: 'SESSION',
  secret: [crypto.randomBytes(32).toString('hex')],
  resave: false,
  saveUninitialized: true
}))

app.use(errorHandler);

/**
 * routes
 */
app.get('/', async (req: express.Request, res: express.Response) => {
  if (req.session.tokenSet) {
    console.log('received tokens %j', req.session.tokenSet);
    return res.send('OK');
  }
  const state = generators.state();
  req.session.state = state;

  const codeVerifier = generators.codeVerifier();
  const codeChallenge = generators.codeChallenge(codeVerifier);
  req.session.codeVerifier = codeVerifier;

  const nonce = generators.nonce();
  req.session.nonce = nonce;

  const url = client.authorizationUrl({
    scope: 'openid',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })
  req.session.originalUrl = req.originalUrl;
  req.session.authorized = true;
  return res.redirect(url);
});

app.get('/cb', async (req: express.Request, res: express.Response) => {
  if (!req.session.authorized) {
    return res.status(403).send('NG');
  }
  const state = req.session.state;
  const codeVerifier = req.session.codeVerifier;
  const nonce = req.session.nonce;
  const params = client.callbackParams(req);
  const tokenSet = await client.callback(
    undefined,
    params,
    {
      state,
      nonce,
      code_verifier: codeVerifier
    });
  console.log('received and validated tokens %j', tokenSet);
  req.session.tokenSet = tokenSet;
  res.send('OK')
});

app.listen(PORT, () => {
  console.log(`listen port: ${PORT}`);
});