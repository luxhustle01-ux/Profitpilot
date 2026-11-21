#!/usr/bin/env node
// B25: local, disposable protocol-level staging. No production accounts/data.
// The outer process creates an ephemeral CA and TLS PostgreSQL service. The
// child starts with NODE_EXTRA_CA_CERTS and tests actual PostgreSQL TLS plus
// JOSE verification against an HTTPS synthetic issuer mapped to loopback.
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {randomBytes} from "node:crypto";
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,chmodSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {fileURLToPath} from "node:url";

const staging=process.env.PROFITPILOT_B25_STAGING_DIR;
function run(cmd,args,{input,env=process.env,timeout=30_000}={}){
 const result=spawnSync(cmd,args,{encoding:"utf8",input,env,timeout,
  maxBuffer:1024*1024});
 if(result.error||result.signal||result.status!==0)
  throw Error("B25 isolated staging command failed: "+cmd+" (exit "+result.status+")");
 return (result.stdout||"").trim();
}
async function exercise(){
 const {createServer:secureServer}=await import("node:https");
 const {createServer:httpServer}=await import("node:http");
 const {generateKeyPair,exportJWK,SignJWT}=await import("jose");
 const pg=(await import("pg")).default;
 const express=(await import("express")).default;
 const {databaseConfig,protectedStartupPreflight}=await import("../server/deployment.js");
 const {authRequired,identityConfig}=await import("../server/auth.js");
 const ca=readFileSync(join(staging,"ca.crt"),"utf8");
 const dbHost="localhost";
 const port=Number(process.env.PROFITPILOT_B25_PG_PORT);
 assert.ok(Number.isInteger(port)&&port>1024&&port<65536);
 const passwd=process.env.PROFITPILOT_B25_DB_PASSWORD;
 assert.match(passwd,/^[a-f0-9]{64}$/);
 const dbUrl="postgresql://postgres:"+passwd+"@"+dbHost+":"+port+"/profitpilot_b25";
 const secretDir=join(staging,"secrets");
 mkdirSync(secretDir,{mode:0o700});
 const dbFile=join(secretDir,"database-url"),keyFile=join(secretDir,"tenant-signing-key");
 writeFileSync(dbFile,dbUrl+"\n",{mode:0o600});
 writeFileSync(keyFile,randomBytes(32).toString("hex")+"\n",{mode:0o600});
 const oldEnv={...process.env};
 const issuer="https://issuer-ci.invalid/";
 const keyPair1=await generateKeyPair("RS256");
 const keyPair2=await generateKeyPair("RS256");
 const jwk1=await exportJWK(keyPair1.publicKey);
 const jwk2=await exportJWK(keyPair2.publicKey);
 for(const [key,kid] of [[jwk1,"b25-key-1"],[jwk2,"b25-key-2"]]){
  key.kid=kid;key.alg="RS256";key.use="sig";
 }
 const jwks=secureServer({
  key:readFileSync(join(staging,"issuer.key")),
  cert:readFileSync(join(staging,"issuer.crt"))
 },(req,res)=>{
  // Synthetic IdP failures must never result in granting access to an
  // otherwise valid token when there is no trusted JWKS for this endpoint.
  if(req.url==="/jwks-unavailable"){
   res.writeHead(503,{"content-type":"application/json","cache-control":"no-store"});
   res.end(JSON.stringify({error:"synthetic outage"}));return;
  }
  if(req.url==="/jwks-malformed"){
   res.writeHead(200,{"content-type":"application/json","cache-control":"no-store"});
   res.end(JSON.stringify({keys:"not-a-JWKS-array"}));return;
  }
  if(req.url!=="/jwks"){res.writeHead(404).end();return;}
  res.writeHead(200,{"content-type":"application/json","cache-control":"no-store"});
  res.end(JSON.stringify({keys:[jwk1,jwk2]}));
 });
 const listen=(server)=>new Promise((resolve,reject)=>{
  server.once("error",reject);
  server.listen(0,"127.0.0.1",resolve);
 });
 const close=(server)=>new Promise(resolve=>server.close(()=>resolve()));
 let api;
 try{
  await listen(jwks);
  const jwksPort=jwks.address().port;
  Object.assign(process.env,{
   NODE_ENV:"production",PROFITPILOT_PROFILE:"protected",
   DATABASE_SSL:"true",MALWARE_SCAN_MODE:"clamav",AUTH_MFA_ACR:"ci-verified-mfa",
   DATABASE_URL_FILE:dbFile,TENANT_CONTEXT_HMAC_SECRET_FILE:keyFile,
   AUTH_ISSUER:issuer,AUTH_AUDIENCE:"profitpilot-b25",
   AUTH_JWKS_URL:"https://issuer-ci.invalid:"+jwksPort+"/jwks"
  });
  delete process.env.DATABASE_URL;
  delete process.env.TENANT_CONTEXT_HMAC_SECRET;
  assert.equal(protectedStartupPreflight().mountedSecretsVerified,true);
  assert.equal(identityConfig().url.protocol,"https:");
  const cfg=databaseConfig();
  assert.deepEqual(cfg.ssl,{rejectUnauthorized:true},
   "protected DB must require certificate verification");

  const pool=new pg.Pool({...cfg,max:1,connectionTimeoutMillis:3000});
  try{
   let tlsInfo;
   for(let tries=0;tries<25;tries++){
    try{
     tlsInfo=await pool.query("SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()");
     break;
    }catch(error){
     if(tries===24)throw Error("B25 strict verified PostgreSQL TLS connection unavailable");
     await new Promise(r=>setTimeout(r,250));
    }
   }
   assert.equal(tlsInfo.rows[0].ssl,true,"Actual PostgreSQL TLS must be active");
   assert.match(tlsInfo.rows[0].version,/TLSv1\.[23]/);
   assert.ok(tlsInfo.rows[0].cipher,"TLS cipher must be negotiated");
   console.log("B25 PASS: real PostgreSQL TLS handshake with verified CA and active TLS session");
  }finally{await pool.end();}
  async function rejectDb({url=dbUrl,ssl,verifyError},label){
   const c=new pg.Client({connectionString:url,ssl,connectionTimeoutMillis:2000});
   try{
    // A generic DNS failure or ECONNREFUSED is NOT proof that the
    // PostgreSQL HBA or TLS peer identity actually rejected this client.
    await assert.rejects(c.connect(),error=>Boolean(verifyError(error)),label);
   }finally{await c.end().catch(()=>{});}
   console.log("B25 correctly denied PostgreSQL connection: "+label);
  }
  await rejectDb({ssl:false,verifyError:error=>
   error?.code==="28000"&&/pg_hba.conf|rejects connection|no encryption/i.test(error.message)
  },"plaintext TCP prohibited by hostnossl HBA");
  // Deliberately change the client *connection hostname* to a separate
  // loopback alias omitted from the certificate SAN. Supplying only an
  // ssl.servername option is not a reliable hostname test in node-postgres:
  // the connection host may take precedence over that field.
  await rejectDb({
    url:dbUrl.replace("@localhost:","@invalid-db-host-ci.invalid:"),
    ssl:{rejectUnauthorized:true},
    verifyError:error=>error?.code==="ERR_TLS_CERT_ALTNAME_INVALID"||
      /Hostname\/IP does not match certificate/i.test(error?.message||"")
   },"mismatched TLS certificate hostname");

  const app=express();
  app.get("/read",authRequired(),(req,res)=>res.json({ok:true,sub:req.identity.subject}));
  app.post("/write",authRequired(),(req,res)=>res.json({ok:true}));
  api=httpServer(app);await listen(api);
  const endpoint="http://127.0.0.1:"+api.address().port;
  const now=Math.floor(Date.now()/1000);
  async function token({pair=keyPair1,kid="b25-key-1",
   tokenIssuer=issuer,audience="profitpilot-b25",acr="ci-verified-mfa",
   authTime=now,expire=now+300}={}){
   return new SignJWT({acr,auth_time:authTime})
    .setProtectedHeader({alg:"RS256",kid})
    .setIssuer(tokenIssuer).setAudience(audience).setSubject("ci-synthetic-operator")
    .setIssuedAt(now).setExpirationTime(expire).sign(pair.privateKey);
  }
  async function request(path,jwt,method="GET"){
   const headers=jwt?{authorization:"Bearer "+jwt}:{};
   return fetch(endpoint+path,{method,headers,signal:AbortSignal.timeout(5000)});
  }
  assert.equal((await request("/read")).status,401,"missing bearer token");
  assert.equal((await request("/read",await token())).status,200,"trusted MFA JWT");
  assert.equal((await request("/write",await token(),"POST")).status,200,
   "fresh MFA required for writes");
  assert.equal((await request("/read",await token({acr:"password-only"}))).status,403,
   "unverified MFA must fail");
  assert.equal((await request("/write",await token({authTime:now-3600}),"POST")).status,403,
   "stale MFA must be refused for writes");
  assert.equal((await request("/read",await token({tokenIssuer:"https://wrong-ci.invalid/"}))).status,401,
   "wrong signed issuer must be refused");
  assert.equal((await request("/read",await token({audience:"wrong-audience"}))).status,401,
   "wrong signed audience must be refused");
  assert.equal((await request("/read",await token({expire:now-60}))).status,401,
   "expired JWT must be refused");
  assert.equal((await request("/read",await token({pair:keyPair2,kid:"b25-key-2"}))).status,200,
   "valid second JWKS key must be accepted during controlled overlap");
  const unknown=await generateKeyPair("RS256");
  assert.equal((await request("/read",await token({pair:unknown,kid:"unknown-key"}))).status,401,
   "unknown JWKS signing key must be refused");
  // Changing the configured trusted endpoint creates a new verifier with
  // no cached keys. A 503 or malformed trusted HTTPS response MUST deny
  // even a correctly signed JWT and recovery must require valid JWKS data.
  const regularJwksUrl=process.env.AUTH_JWKS_URL;
  const authenticated=await token();
  for(const endpointPath of ["/jwks-unavailable","/jwks-malformed"]){
   process.env.AUTH_JWKS_URL="https://issuer-ci.invalid:"+jwksPort+endpointPath;
   const denied=await request("/read",authenticated);
   assert.equal(denied.status,401,"Unavailable or malformed JWKS must fail closed");
   assert.equal((await denied.json()).error,"Invalid or expired access token");
  }
  process.env.AUTH_JWKS_URL=regularJwksUrl;
  assert.equal((await request("/read",authenticated)).status,200,
   "Valid JWKS must be required for recovery after endpoint failures");
  console.log("B28 PASS: isolated HTTPS JWKS 503 and malformed responses denied access; valid JWKS recovery permitted");
  console.log("B25 PASS: HTTPS JWKS trust and JWT issuer/audience/expiry/MFA checks; two overlapping keys accepted, unknown key rejected");
  console.log("B25 LIMIT: live IdP outage/revocation behaviour, DNS egress policy and key-cache eviction are not proved by loopback synthetic issuer");
 }finally{
  if(api)await close(api);
  await close(jwks).catch(()=>{});
  for(const k of ["NODE_ENV","PROFITPILOT_PROFILE","DATABASE_SSL","MALWARE_SCAN_MODE",
   "AUTH_MFA_ACR","DATABASE_URL_FILE","TENANT_CONTEXT_HMAC_SECRET_FILE",
   "AUTH_ISSUER","AUTH_AUDIENCE","AUTH_JWKS_URL"]){
   if(Object.hasOwn(oldEnv,k))process.env[k]=oldEnv[k];else delete process.env[k];
  }
 }
}
function outer(){
 if(process.platform!=="linux"||process.env.CI!=="true"||
    typeof process.getuid!=="function"||process.getuid()===0)
  throw Error("B25 local protocol staging requires unprivileged Linux CI runner");
 const root=mkdtempSync(join(tmpdir(),"pp-b25-tls-"));
 const container="profitpilot-b25-pg-"+randomBytes(6).toString("hex");
 try{
  chmodSync(root,0o755);
  const password=randomBytes(32).toString("hex");
  run("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-days","1",
   "-subj","/CN=ProfitPilot B25 Synthetic CA","-keyout",join(root,"ca.key"),
   "-out",join(root,"ca.crt")]);
  run("openssl",["req","-newkey","rsa:2048","-nodes",
   "-subj","/CN=issuer-ci.invalid","-keyout",join(root,"server.key"),
   "-out",join(root,"server.csr")]);
  writeFileSync(join(root,"server.ext"),
   "basicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost,DNS:issuer-ci.invalid\nextendedKeyUsage=serverAuth\n",{mode:0o644});
  run("openssl",["x509","-req","-in",join(root,"server.csr"),
   "-CA",join(root,"ca.crt"),"-CAkey",join(root,"ca.key"),"-CAcreateserial",
   "-days","1","-out",join(root,"server.crt"),"-extfile",join(root,"server.ext")]);
  // Separate issuer certificate avoids sharing a TLS private key between
  // PostgreSQL (owned by its container UID) and the host HTTPS test server.
  run("openssl",["req","-newkey","rsa:2048","-nodes",
   "-subj","/CN=issuer-ci.invalid","-keyout",join(root,"issuer.key"),
   "-out",join(root,"issuer.csr")]);
  run("openssl",["x509","-req","-in",join(root,"issuer.csr"),
   "-CA",join(root,"ca.crt"),"-CAkey",join(root,"ca.key"),"-CAcreateserial",
   "-days","1","-out",join(root,"issuer.crt"),"-extfile",join(root,"server.ext")]);
  chmodSync(join(root,"issuer.key"),0o600);
  const postgresUid=Number(run("docker",["run","--rm","--entrypoint","id","postgres:16-alpine","-u","postgres"]));
  assert.ok(Number.isSafeInteger(postgresUid)&&postgresUid>0);
  // Set restrictive mode while still owned by the unprivileged runner.
  // Chowning first would make a subsequent chmod fail with EPERM.
  chmodSync(join(root,"server.key"),0o600);
  run("sudo",["chown",String(postgresUid)+":"+String(postgresUid),join(root,"server.key")]);
  writeFileSync(join(root,"pg_hba.conf"),[
   "local all all trust",
   "hostnossl all all 0.0.0.0/0 reject",
   "hostssl all all 0.0.0.0/0 scram-sha-256",
   "hostnossl all all ::/0 reject",
   "hostssl all all ::/0 scram-sha-256",
   ""
  ].join("\n"),{mode:0o644});
  run("sudo",["tee","-a","/etc/hosts"],{
   input:"127.0.0.1 issuer-ci.invalid invalid-db-host-ci.invalid # PROFITPILOT_B25_SYNTHETIC\n"
  });
  run("docker",["run","--detach","--rm","--name",container,
   "--publish","127.0.0.1::5432",
   "--mount","type=bind,source="+root+",target=/certs,readonly",
   "--env","POSTGRES_PASSWORD="+password,
   "--env","POSTGRES_DB=profitpilot_b25",
   "postgres:16-alpine",
   "-c","ssl=on",
   "-c","ssl_cert_file=/certs/server.crt",
   "-c","ssl_key_file=/certs/server.key",
   "-c","hba_file=/certs/pg_hba.conf"]);
  const published=run("docker",["port",container,"5432/tcp"]);
  const m=/^127\.0\.0\.1:(\d+)$/.exec(published);
  if(!m)throw Error("B25 PostgreSQL staging must be published only on host loopback");
  const env={...process.env,
   PROFITPILOT_B25_STAGING_DIR:root,
   PROFITPILOT_B25_PG_PORT:m[1],
   PROFITPILOT_B25_DB_PASSWORD:password,
   NODE_EXTRA_CA_CERTS:join(root,"ca.crt"),
   NODE_OPTIONS:"--dns-result-order=ipv4first"};
  const child=spawnSync(process.execPath,[fileURLToPath(import.meta.url),"child"],
   {env,stdio:"inherit",timeout:90_000});
  if(child.status!==0||child.error||child.signal)
   throw Error("B25 isolated protocol-level staging failed");
 }finally{
  try{run("docker",["rm","-f",container],{timeout:15_000});}catch{}
  try{
   run("sudo",["chown","-R",String(process.getuid())+":"+String(process.getgid()),root]);
   rmSync(root,{recursive:true,force:true});
  }catch{throw Error("B25 temporary TLS material cleanup failed");}
 }
}
try{
 if(process.argv[2]==="child")await exercise();else outer();
}catch(error){
 // Never print synthetic passwords, signing keys or certificate private material.
 console.error("B25 FAIL:",error.message.replace(/postgresql:\/\/[^ ]+/g,"[database-url-redacted]"));
 process.exitCode=1;
}
