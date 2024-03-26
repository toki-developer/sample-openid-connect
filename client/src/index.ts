import express from "express";
import { Issuer } from "openid-client";

const app = express();
const port = 4000;

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
  const authorizationUri = client.authorizationUrl({
    redirect_uri: "http://localhost:4000/oidc/callback",
    scope: "openid",
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
        }),
      }
    );
    const tokenSet = await tokenResponse.json();
    console.log(tokenSet);
    // TODO: トークンを検証するコードは後で追加します
    res.status(200);
    res.json({ tokenSet });
    return;
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