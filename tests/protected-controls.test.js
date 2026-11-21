import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,chmodSync,symlinkSync,linkSync,unlinkSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {inspect} from "node:util";
import {deploymentProfile,databaseConfig,readSecret,validMfa,protectedCorsOrigins,protectedStartupPreflight,enforceProtectedImageProfile} from "../server/deployment.js";
test("protected profile rejects missing prerequisites and TLS overrides",()=>{
 const dir=mkdtempSync(join(tmpdir(),"pp-config-"));
 try{
  const url=join(dir,"url"),key=join(dir,"key");
  writeFileSync(url,"postgres://app@db.invalid/profitpilot\n",{mode:0o600});writeFileSync(key,"a".repeat(64),{mode:0o600});
  const env={NODE_ENV:"production",PROFITPILOT_PROFILE:"protected",DATABASE_SSL:"true",DATABASE_URL_FILE:url,TENANT_CONTEXT_HMAC_SECRET_FILE:key,AUTH_MFA_ACR:"trusted-mfa",MALWARE_SCAN_MODE:"clamav"};
  assert.throws(()=>deploymentProfile({NODE_ENV:"production"}));
  for(const k of ["DATABASE_SSL","DATABASE_URL_FILE","TENANT_CONTEXT_HMAC_SECRET_FILE","AUTH_MFA_ACR","MALWARE_SCAN_MODE"])assert.throws(()=>deploymentProfile({...env,[k]:undefined}));
  assert.deepEqual(databaseConfig(env).ssl,{rejectUnauthorized:true});
  assert.equal(readSecret("TENANT_CONTEXT_HMAC_SECRET",env),"a".repeat(64));
  chmodSync(key,0o644);
  assert.throws(()=>readSecret("TENANT_CONTEXT_HMAC_SECRET",env),/owner-only permissions/);
  chmodSync(key,0o600);
  const link=join(dir,"linked-key");symlinkSync(key,link);
  assert.throws(()=>readSecret("TENANT_CONTEXT_HMAC_SECRET",{...env,TENANT_CONTEXT_HMAC_SECRET_FILE:link}));
  assert.throws(()=>readSecret("DATABASE_URL",{...env,DATABASE_URL:"ambiguous"}));
  for(const invalid of ["postgres://app@db.invalid/profitpilot?sslmode=disable","postgres://app@db.invalid/profitpilot?options=-c%20statement_timeout=0","postgres://app@db.invalid/profitpilot?host=other.invalid","postgres://app@db.invalid/profitpilot#x","postgres://app@db.invalid/"]){writeFileSync(url,invalid);assert.throws(()=>databaseConfig(env));}
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test("MFA checks trusted assurance and fresh signed authentication time",()=>{
 assert.ok(validMfa({acr:"strong",auth_time:100},"strong",500,900));
 for(const p of [{acr:"weak",auth_time:100},{acr:"strong"},{acr:"strong",auth_time:2000},{acr:"strong",auth_time:-1000}])assert.equal(validMfa(p,"strong",500,900),false);
});

test("mounted secret input is bounded and must be a nonempty regular UTF-8 file",()=>{
 const dir=mkdtempSync(join(tmpdir(),"pp-secret-"));
 try{
  const path=join(dir,"secret"),env={TEST_SECRET_FILE:path};
  for(const value of [""," ","x".repeat(8193),Buffer.from([0xff])]){
   writeFileSync(path,value);
   assert.throws(()=>readSecret("TEST_SECRET",env));
  }
  writeFileSync(path,"x".repeat(8192));
  assert.equal(readSecret("TEST_SECRET",env).length,8192);
  assert.equal(readSecret("TEST_SECRET",{...env,TEST_SECRET:""}).length,8192);
  assert.throws(()=>readSecret("TEST_SECRET",{...env,TEST_SECRET:"conflict"}),/Ambiguous secret configuration/);
  assert.throws(()=>readSecret("TEST_SECRET",{TEST_SECRET_FILE:dir}));
 }finally{rmSync(dir,{recursive:true,force:true});}
});

test("B14 protected runtime rejects nonproduction NODE_ENV even with all security inputs",()=>{
 const env={NODE_ENV:"production",PROFITPILOT_PROFILE:"protected",DATABASE_SSL:"true",
  DATABASE_URL_FILE:"/unused/mount",TENANT_CONTEXT_HMAC_SECRET_FILE:"/unused/mount2",
  AUTH_MFA_ACR:"verified-mfa",MALWARE_SCAN_MODE:"clamav"};
 assert.equal(deploymentProfile(env).protectedMode,true);
 for(const mode of ["test","development","",undefined])
  assert.throws(()=>deploymentProfile({...env,NODE_ENV:mode}),/requires NODE_ENV=production/);
 assert.equal(deploymentProfile({...env,CORS_ORIGIN:"https://dashboard.example.com"}).corsOrigins[0],
   "https://dashboard.example.com");
});

test("B14 protected browser origins are exact HTTPS origins or empty-deny",()=>{
 assert.deepEqual(protectedCorsOrigins(undefined),[]);
 assert.deepEqual(protectedCorsOrigins(""),[]);
 assert.deepEqual(protectedCorsOrigins("https://app.example.com, https://admin.example.com"),
  ["https://app.example.com","https://admin.example.com"]);
 for(const bad of [
  "*","https://*.example.com","http://app.example.com",
  "https://app.example.com/route","https://app.example.com/",
  "https://admin:password@app.example.com","https://app.example.com?x=1",
  "https://app.example.com#frag","https://app.example.com,https://app.example.com",
  "https://app.example.com,,https://other.example.com",
  "https://localhost","https://127.0.0.1","https://internal.localhost",
  "https://app.example.com,"+"https://a.example.com,".repeat(9)+"https://z.example.com"
 ])assert.throws(()=>protectedCorsOrigins(bad),bad);
});


function protectedSecretFixture(){
 const dir=mkdtempSync(join(tmpdir(),"pp-b22-mount-"));
 const db=join(dir,"database-url");
 const key=join(dir,"signing-key");
 writeFileSync(db,"postgres://app@db.invalid/profitpilot\n",{mode:0o600});
 writeFileSync(key,"a".repeat(64)+"\n",{mode:0o600});
 const env={NODE_ENV:"production",PROFITPILOT_PROFILE:"protected",DATABASE_SSL:"true",
  DATABASE_URL_FILE:db,TENANT_CONTEXT_HMAC_SECRET_FILE:key,
  MALWARE_SCAN_MODE:"clamav",AUTH_MFA_ACR:"trusted-mfa"};
 return {dir,db,key,env,cleanup:()=>rmSync(dir,{recursive:true,force:true})};
}

test("B22 protected preflight verifies mounted DB and signing-key files before startup",()=>{
 const h=protectedSecretFixture();
 try{
  const verified=protectedStartupPreflight(h.env);
  assert.equal(verified.mountedSecretsVerified,true);
  assert.equal(verified.productionReleaseApproved,false);
  assert.equal(verified.liveInfrastructureVerified,false);
  assert.equal(readSecret("TENANT_CONTEXT_HMAC_SECRET",h.env),"a".repeat(64));
  assert.equal(readSecret("DATABASE_URL",h.env),"postgres://app@db.invalid/profitpilot");
  assert.throws(()=>protectedStartupPreflight({
   ...h.env,DATABASE_URL_FILE:join(h.dir,"missing-db-secret")
  }),error=>error.message.includes("DATABASE_URL")&&!error.message.includes(h.dir));
  chmodSync(h.key,0o400);
  assert.equal(protectedStartupPreflight(h.env).mountedSecretsVerified,true);
  chmodSync(h.key,0o600);
  for(const invalid of [
   {...h.env,DATABASE_URL_FILE:join(h.dir,"missing")},
   {...h.env,TENANT_CONTEXT_HMAC_SECRET_FILE:join(h.dir,"missing")},
   {...h.env,DATABASE_URL:""},
   {...h.env,TENANT_CONTEXT_HMAC_SECRET:""},
   {...h.env,DATABASE_URL_FILE:"relative/secret"},
   {...h.env,TENANT_CONTEXT_HMAC_SECRET_FILE:h.key+"/../bad"},
  ])assert.throws(()=>protectedStartupPreflight(invalid));
  writeFileSync(h.key,"weak",{mode:0o600});
  assert.throws(()=>protectedStartupPreflight(h.env),/Invalid mounted tenant-context signing key/);
 }finally{h.cleanup();}
});

test("B22 protected secret path rejects symlinked parents, writable parents and aliasing hardlinks",()=>{
 const h=protectedSecretFixture();
 try{
  const safe=join(h.dir,"safe");
  mkdirSync(safe,{mode:0o700});
  const nested=join(safe,"key");
  writeFileSync(nested,"b".repeat(64),{mode:0o600});
  assert.equal(readSecret("TENANT_CONTEXT_HMAC_SECRET",
   {...h.env,TENANT_CONTEXT_HMAC_SECRET_FILE:nested}),"b".repeat(64));
  const alias=join(h.dir,"parent-link");
  symlinkSync(safe,alias);
  assert.throws(()=>readSecret("TENANT_CONTEXT_HMAC_SECRET",
   {...h.env,TENANT_CONTEXT_HMAC_SECRET_FILE:join(alias,"key")}),
   /Untrusted protected secret directory or symlink/);
  chmodSync(safe,0o770);
  assert.throws(()=>readSecret("TENANT_CONTEXT_HMAC_SECRET",
   {...h.env,TENANT_CONTEXT_HMAC_SECRET_FILE:nested}),
   /Writable protected secret ancestor/);
  chmodSync(safe,0o700);
  const hardlink=join(safe,"hardlink");
  linkSync(nested,hardlink);
  assert.throws(()=>readSecret("TENANT_CONTEXT_HMAC_SECRET",
   {...h.env,TENANT_CONTEXT_HMAC_SECRET_FILE:nested}),
   /ownership or hardlink count/);
  unlinkSync(hardlink);
  assert.equal(readSecret("TENANT_CONTEXT_HMAC_SECRET",
   {...h.env,TENANT_CONTEXT_HMAC_SECRET_FILE:nested}),"b".repeat(64));
 }finally{h.cleanup();}
});

test("B22 protected secrets require owner-only nonexecutable permissions and unmodified text",()=>{
 const h=protectedSecretFixture();
 try{
  for(const mode of [0o640,0o644,0o700,0o711]){
   chmodSync(h.key,mode);
   assert.throws(()=>readSecret("TENANT_CONTEXT_HMAC_SECRET",h.env),
    /owner-only permissions/);
  }
  chmodSync(h.key,0o600);
  for(const invalidText of [" b","b ","b\nc","b\rc","b\0c","b\tc","\n"]){
   writeFileSync(h.key,invalidText,{mode:0o600});
   assert.throws(()=>readSecret("TENANT_CONTEXT_HMAC_SECRET",h.env));
  }
  for(const valid of ["b","b\n","b\r\n"]){
   writeFileSync(h.key,valid,{mode:0o600});
   assert.equal(readSecret("TENANT_CONTEXT_HMAC_SECRET",h.env),"b");
  }
  writeFileSync(h.key,"b".repeat(8193),{mode:0o600});
  assert.throws(()=>readSecret("TENANT_CONTEXT_HMAC_SECRET",h.env),
   /Invalid mounted secret/);
 }finally{h.cleanup();}
});

test("B22 protected startup rejects a symlinked signing-key mount even with apparently valid contents",()=>{
 const h=protectedSecretFixture();
 try{
  const link=join(h.dir,"link-to-key");
  symlinkSync(h.key,link);
  assert.throws(()=>protectedStartupPreflight({
   ...h.env,TENANT_CONTEXT_HMAC_SECRET_FILE:link
  }),/owner-only permissions/);
  assert.throws(()=>protectedStartupPreflight({
   ...h.env,TENANT_CONTEXT_HMAC_SECRET_FILE:h.key,DATABASE_URL_FILE:link
  }),/owner-only permissions/);
 }finally{h.cleanup();}
});

test("B26 protected scanner image cannot downgrade to prototype, regardless of environment flags",()=>{
 assert.throws(()=>enforceProtectedImageProfile("prototype",true),
  /Protected image refuses prototype profile downgrade/);
 assert.doesNotThrow(()=>enforceProtectedImageProfile("protected",true));
 assert.doesNotThrow(()=>enforceProtectedImageProfile("prototype",false));
});

test("B27 malformed protected database URL never exposes mounted credentials in exception metadata",()=>{
 const h=protectedSecretFixture();
 try{
  const marker="b27-synthetic-url-password-marker";
  writeFileSync(h.db,"postgresql://app:"+marker+"@bad host/profitpilot\n",{mode:0o600});
  assert.throws(()=>databaseConfig(h.env),error=>{
   assert.equal(error.message,"Protected database URL is invalid");
   assert.equal(Object.hasOwn(error,"input"),false);
   assert.ok(!inspect(error).includes(marker),"Node error inspection leaked database credentials");
   assert.ok(!String(error.stack).includes(marker),"Stack leaked database credentials");
   assert.ok(!JSON.stringify(error).includes(marker),"JSON error leaked database credentials");
   return true;
  });
 }finally{h.cleanup();}
});

test("B25 protected profile refuses process-wide TLS verification disablement",()=>{
 const env={NODE_ENV:"production",PROFITPILOT_PROFILE:"protected",DATABASE_SSL:"true",
  DATABASE_URL_FILE:"/run/secrets/db",TENANT_CONTEXT_HMAC_SECRET_FILE:"/run/secrets/key",
  MALWARE_SCAN_MODE:"clamav",AUTH_MFA_ACR:"verified-mfa"};
 assert.equal(deploymentProfile(env).protectedMode,true);
 assert.equal(deploymentProfile({...env,NODE_TLS_REJECT_UNAUTHORIZED:"1"}).protectedMode,true);
 assert.throws(()=>deploymentProfile({...env,NODE_TLS_REJECT_UNAUTHORIZED:"0"}),
  /forbids disabling TLS certificate verification/);
});
