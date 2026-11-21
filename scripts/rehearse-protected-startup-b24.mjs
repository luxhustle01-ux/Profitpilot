#!/usr/bin/env node
// B24: isolated synthetic protected image rehearsal. No live services or secrets.
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import {mkdtempSync,mkdirSync,writeFileSync,chmodSync,symlinkSync,linkSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {spawnSync} from "node:child_process";

const image=process.env.PROFITPILOT_B24_IMAGE||"profitpilot-protected:ci";
if(!/^profitpilot-protected:[A-Za-z0-9_.-]+$/.test(image))
 throw Error("B24 requires a named, built protected image");
if(process.platform!=="linux"||typeof process.getuid!=="function"||
 process.getuid()===0||process.env.CI!=="true")
 throw Error("B24 requires an unprivileged Linux GitHub CI runner");
const root=mkdtempSync(join(tmpdir(),"profitpilot-b24-"));
const container="profitpilot-b24-"+randomBytes(8).toString("hex");
const signingKey=randomBytes(32).toString("hex");
const databaseUrl="postgresql://synthetic_app:synthetic_only@no-db.invalid/profitpilot";
let started=false;

function command(executable,args,timeout=30_000){
 const r=spawnSync(executable,args,{encoding:"utf8",timeout,maxBuffer:2*1024*1024});
 if(r.error)throw Error("B24 command failed: "+executable+" ("+r.error.code+")");
 return {status:r.status,signal:r.signal,output:(r.stdout||"")+(r.stderr||"")};
}
function mustRun(executable,args,timeout){
 const r=command(executable,args,timeout);
 if(r.status!==0||r.signal)
  throw Error("B24 CI infrastructure command failed: "+executable+" ("+r.status+")");
 return r.output;
}
function fixture(name,{db=databaseUrl,key=signingKey,dbMode=0o600,
 keyMode=0o400,dirMode=0o700}={}){
 const dir=join(root,name);
 mkdirSync(dir,{mode:0o700});
 writeFileSync(join(dir,"db-url"),db+"\n",{mode:dbMode});
 writeFileSync(join(dir,"key"),key+"\n",{mode:keyMode});
 chmodSync(dir,dirMode);
}
const baseEnv={
 NODE_ENV:"production",PROFITPILOT_PROFILE:"protected",PORT:"8080",
 DATABASE_SSL:"true",MALWARE_SCAN_MODE:"clamav",AUTH_MFA_ACR:"ci-mfa",
 AUTH_ISSUER:"https://ci-issuer.invalid/",AUTH_AUDIENCE:"profitpilot-ci",
 AUTH_JWKS_URL:"https://ci-issuer.invalid/jwks",
 DATABASE_URL_FILE:"/run/secrets/good/db-url",
 TENANT_CONTEXT_HMAC_SECRET_FILE:"/run/secrets/good/key"
};
function argsFor(env,detached=false){
 return [
  "run","--rm",...(detached?["--detach","--name",container]:[]),
  "--network","none","--read-only",
  "--tmpfs","/tmp:rw,noexec,nosuid,size=16m",
  "--cap-drop","ALL","--security-opt","no-new-privileges",
  "--pids-limit","64","--memory","256m","--user","1000:1000",
  "--mount","type=bind,source="+root+",target=/run/secrets,readonly",
  ...Object.entries(env).flatMap(([name,value])=>["--env",name+"="+value]),
  image,"/usr/local/bin/node","server/index.js"
 ];
}
function negative(name,changes,expected){
 const r=command("timeout",["12s","docker",...argsFor({...baseEnv,...changes})],16_000);
 if(r.status===0||r.status===124||r.status===125||r.signal||
    !expected.test(r.output)||r.output.includes(signingKey))
  throw Error("B24 fail-closed startup regression: "+name+
   " (status "+r.status+", expected rejection: "+expected.test(r.output)+")");
 console.log("B24 correctly rejected protected startup: "+name);
}
function positive(){
 mustRun("docker",argsFor(baseEnv,true),20_000);
 started=true;
 // Independently inspect effective Docker runtime settings rather than
 // trusting our own CLI flags to establish confinement.
 const host=JSON.parse(mustRun("docker",["inspect","--format","{{json .HostConfig}}",container],10_000));
 assert.equal(host.NetworkMode,"none","Unexpected container network access");
 assert.equal(host.ReadonlyRootfs,true,"Protected container rootfs must be read-only");
 assert.equal(host.Privileged,false,"Protected container must not be privileged");
 assert.ok(Array.isArray(host.CapDrop)&&host.CapDrop.includes("ALL"),
  "Protected container must drop all Linux capabilities");
 assert.equal(Object.keys(host.PortBindings||{}).length,0,
  "Protected container must not publish ports");
 const probe=[
  'import assert from "node:assert/strict";',
  'import {statSync,openSync,constants} from "node:fs";',
  'assert.equal(process.getuid(),1000);',
  'assert.equal(statSync("/run/secrets/good/key").mode&0o777,0o400);',
  // The DB secret has mode 0600 and is owned by UID 1000; denial of opening
  // it for writing must therefore be caused by the immutable bind mount.
  'assert.throws(()=>openSync("/run/secrets/good/db-url",constants.O_WRONLY),error=>error.code==="EROFS");',
  'let unauth;',
  'for(let i=0;i<30;i++){',
  ' try{unauth=await fetch("http://127.0.0.1:8080/v1/me",{headers:{Origin:"https://untrusted.invalid"},signal:AbortSignal.timeout(2000)});break;}',
  ' catch(error){if(i===29)throw error;await new Promise(resolve=>setTimeout(resolve,150));}',
  '}',
  'assert.equal(unauth.status,401,"Bearer authentication must be required");',
  'assert.equal(unauth.headers.get("access-control-allow-origin"),null,"Unexpected browser cross-origin access");',
  'const health=await fetch("http://127.0.0.1:8080/health",{signal:AbortSignal.timeout(10000)});',
  'assert.equal(health.status,503,"Offline rehearsal must never claim database readiness");',
  'assert.equal((await health.json()).status,"unavailable");',
  'console.log("B24 protected listener: unauthenticated route denied, CORS denied, offline health unavailable");'
 ].join("\n");
 const r=command("docker",["exec","--user","1000:1000",container,
  "/usr/local/bin/node","--input-type=module","-e",probe],25_000);
 if(r.status!==0||r.signal)
  throw Error("B24 positive protected listener smoke failed (status "+r.status+")");
 const logs=mustRun("docker",["logs",container],10_000);
 assert.match(logs,/ProfitPilot API listening on 8080/);
 assert.ok(!logs.includes(signingKey)&&!logs.includes(databaseUrl),
  "Protected log included synthetic secret");
 console.log("B24 valid protected startup passed with read-only UID-1000 secrets, network disabled, no host ports");
}
try{
 fixture("good");
 fixture("bad-mode",{keyMode:0o644});
 fixture("bad-writable",{dirMode:0o770});
 fixture("bad-key",{key:"weak"});
 fixture("bad-url",{db:databaseUrl+"?sslmode=disable"});
 fixture("bad-controls",{key:"a".repeat(32)+"\n"+"b".repeat(32)});
 fixture("bad-hardlink");
 linkSync(join(root,"bad-hardlink","key"),join(root,"bad-hardlink","key-alias"));
 symlinkSync("good",join(root,"parent-symlink"));
 symlinkSync(join(root,"good","key"),join(root,"final-symlink"));
 fixture("bad-owner");
 // Privileged fixture setup only. Application container itself is nonroot,
 // network disconnected, read-only and has no privileged capabilities.
 mustRun("sudo",["chown","-R","1000:1000",root]);
 mustRun("sudo",["chown","0:0",join(root,"bad-owner","key")]);
 positive();
 negative("missing database file",
  {DATABASE_URL_FILE:"/run/secrets/good/missing"},/Protected mounted secret filesystem access denied: DATABASE_URL/);
 negative("missing signing file",
  {TENANT_CONTEXT_HMAC_SECRET_FILE:"/run/secrets/good/missing"},/Protected mounted secret filesystem access denied: TENANT_CONTEXT_HMAC_SECRET/);
 negative("group/world-readable key",
  {TENANT_CONTEXT_HMAC_SECRET_FILE:"/run/secrets/bad-mode/key"},/owner-only permissions/);
 negative("symlinked parent",
  {DATABASE_URL_FILE:"/run/secrets/parent-symlink/db-url"},/Untrusted protected secret directory or symlink/);
 negative("symlinked final file",
  {TENANT_CONTEXT_HMAC_SECRET_FILE:"/run/secrets/final-symlink"},/owner-only permissions/);
 negative("writable ancestor",
  {DATABASE_URL_FILE:"/run/secrets/bad-writable/db-url"},/Writable protected secret ancestor directory/);
 negative("hardlinked key",
  {TENANT_CONTEXT_HMAC_SECRET_FILE:"/run/secrets/bad-hardlink/key"},/ownership or hardlink count/);
 negative("wrong UID",
  {TENANT_CONTEXT_HMAC_SECRET_FILE:"/run/secrets/bad-owner/key"},/ownership or hardlink count/);
 negative("weak signing key",
  {TENANT_CONTEXT_HMAC_SECRET_FILE:"/run/secrets/bad-key/key"},/Invalid mounted tenant-context signing key/);
 negative("embedded control",
  {TENANT_CONTEXT_HMAC_SECRET_FILE:"/run/secrets/bad-controls/key"},/unsafe whitespace or controls/);
 negative("database TLS override in URL",
  {DATABASE_URL_FILE:"/run/secrets/bad-url/db-url"},/Protected database URL requires a host\/database/);
 negative("ambiguous database environment variable",
  {DATABASE_URL:""},/Ambiguous secret configuration: DATABASE_URL/);
 negative("ambiguous HMAC environment variable",
  {TENANT_CONTEXT_HMAC_SECRET:""},/Ambiguous secret configuration: TENANT_CONTEXT_HMAC_SECRET/);
 negative("TLS disabled",
  {DATABASE_SSL:"false"},/Protected profile requires database TLS/);
 negative("scanner disabled",
  {MALWARE_SCAN_MODE:"disabled"},/Protected profile requires database TLS/);
 negative("untrusted JWKS host",
  {AUTH_JWKS_URL:"https://127.0.0.1/jwks"},/Protected identity endpoints require trusted nonlocal DNS hosts/);
 negative("protected image profile downgrade",
  {PROFITPILOT_PROFILE:"prototype"},
  /Protected image refuses prototype profile downgrade/);
 negative("global TLS verification disabled",
  {NODE_TLS_REJECT_UNAUTHORIZED:"0"},
  /Protected profile forbids disabling TLS certificate verification/);
 console.log("B24+B25 PASS: protected offline startup and 18 distinct startup denials; zero external network");
}catch(error){
 console.error("B24 FAIL:",error.message);
 process.exitCode=1;
}finally{
 if(started)command("docker",["rm","-f",container],10_000);
 try{
  mustRun("sudo",["chown","-R",String(process.getuid())+":"+String(process.getgid()),root]);
  rmSync(root,{recursive:true,force:true});
 }catch(error){console.error("B24 fixture cleanup failed:",error.message);process.exitCode=1;}
}
