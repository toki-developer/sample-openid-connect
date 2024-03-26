import express from "express";
import { Issuer } from "openid-client";
import crypto from "crypto";

import session from "express-session";
const app = express();
const port = 4000;

app.use(
  session({
    secret: "tiny-rp-secret",
    cookie: {},
  })
);
// https://www.typescriptlang.org/docs/handbook/declaration-merging.html#module-augmentation
declare module "express-session" {
  interface SessionData {
    state: string;
    nonce: string;
  }
}


const issuer = new Issuer({
  issuer: "http://localhost:3000",
  authorization_endpoint: "http://localhost:3000/openid-connect/auth",
  token_endpoint: "http://localhost:3000/openid-connect/token",
  jwks_uri: "http://localhost:3000/openid-connect/jwks",
});
const { Client } = issuer;
const client = new Client({
  client_id: "tiny-client",
  client_secret: "hoge",
});

app.get("/", async (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.state = state;
  const nonce = crypto.randomBytes(16).toString("hex");
req.session.nonce = nonce;

  const authorizationUri = client.authorizationUrl({
    redirect_uri: "http://localhost:4000/oidc/callback",
    scope: "openid",
    state,
    nonce
  });
  res.send(`<!DOCTYPE html>
<html>
<head>
    <title>tiny-rp</title>
</head>
<body>
    <div><h1>tiny-idp Login</h1></div>
    <div><a href="${authorizationUri}">Login</a></div>
</body>
</html>`);
});

// redirect_uriをここに実装
// トークンエンドポイントを叩く
app.get("/oidc/callback", async (req, res) => {
  const redirect_uri = "http://localhost:4000/oidc/callback";
  const code = String(req.query.code);
  const scope = String(req.query.scope);
  console.log(req.query.state, req.session.state)

  if (req.session.state !== req.query.state) {
    res.status(400);
    res.json({ error: "invalid state" });
    return;
  }

  try {
    const tokenResponse = await fetch(
      "http://localhost:3000/openid-connect/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          code,
          redirect_uri,
          scope,
          grant_type: "authorization_code",
          client_id: "tiny-client",
          client_secret: "c1!3n753cr37",
        }),
      }
    );
    const configuration = await (
      await fetch(
        "http://localhost:3000/openid-connect/.well-known/openid-configuration"
      )
    ).json();
    const jwksUri = configuration["jwks_uri"];
    const tokenSet = await tokenResponse.json();
    const idToken = tokenSet.id_token;
    if (decodeToken(idToken).payload.nonce !== req.session.nonce) {
      res.status(400);
      res.json({ error: "invalid nonce" });
      return;
    }
    const jwks = await (await fetch(jwksUri)).json();
    const jwk = jwks.keys.find(
      (jwk: any) =>
        jwk.kty === "RSA" && jwk.alg === "RS256" && jwk.use === "sig"
    );
    const verified = verifyToken(idToken, jwk);
    if (verified) {
      res.status(200);
      res.json({ tokenSet });
      return;
    } else {
      res.status(401);
      res.json({ error: "invalid token" });
      return;
    }
  } catch (error) {
    console.error("Access Token Error: ", error);
    res.status(500);
    res.json({ error: "Access Token Error" });
    return;
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});


const base64urlDecode = (input: string) =>{
  input += "=".repeat(4 - (input.length % 4));
  return Buffer.from(
    input.replace(/-/g, "+").replace(/_/g, "/"),
    "base64"
  ).toString("utf-8");
}

const verifyToken = (token: string, jwk: string) => {
  const publicKey = crypto
    .createPublicKey({ key: jwk, format: "jwk" })
    .export({ format: "pem", type: "spki" });

  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
  const signatureData = `${encodedHeader}.${encodedPayload}`;
  const verify = crypto.createVerify("RSA-SHA256");
  verify.update(signatureData);
  const decodedSignature = base64urlDecode(encodedSignature);
  return verify.verify(publicKey, Buffer.from(decodedSignature, "base64"));
};

const decodeToken = (token: string) => {
  const [encodedHeader, encodedPayload, _encodedSignature] = token.split(".");
  const header = JSON.parse(base64urlDecode(encodedHeader));
  const payload = JSON.parse(base64urlDecode(encodedPayload));
  return { header, payload };
};
