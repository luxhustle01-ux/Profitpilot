import {existsSync,openSync,fstatSync,lstatSync,readSync,closeSync,constants} from "node:fs";
import {isAbsolute,parse,resolve,sep,join} from "node:path";

// Protected deployments may explicitly allow only canonical HTTPS browser origins.
// Empty allowlist denies cross-origin browser requests; it is not a wildcard.
export function protectedCorsOrigins(raw){
 if(raw===undefined||raw===null||raw==="")return [];
 if(typeof raw!=="string"||raw.length>2048)throw Error("Invalid protected CORS configuration");
 const origins=raw.split(",").map(x=>x.trim());
 if(origins.length>8||origins.some(x=>!x)||new Set(origins).size!==origins.length)
  throw Error("Invalid or duplicate protected CORS origins");
 for(const origin of origins){
  let url;
  try{url=new URL(origin);}catch{throw Error("Invalid protected CORS origin");}
  if(origin.includes("*")||url.protocol!=="https:"||url.origin!==origin||
    url.username||url.password||url.search||url.hash||url.pathname!=="/"||
    !url.hostname||["localhost","127.0.0.1","0.0.0.0","[::1]"].includes(url.hostname)||
    url.hostname.endsWith(".localhost"))
   throw Error("Protected CORS requires exact HTTPS origins");
 }
 return origins;
}

// The package-managed ClamAV adapter is installed only in the hardened image.
// Its presence is independent of environment-provided profile selection; a
// misconfigured protected image must not silently fall back to prototype mode.
export function enforceProtectedImageProfile(mode,scannerInstalled){
 if(scannerInstalled&&mode!=="protected")
  throw Error("Protected image refuses prototype profile downgrade");
}

// Prototype is synthetic only. Protected mode enforces prerequisites, not release approval.
export function deploymentProfile(env=process.env){
 const mode=env.PROFITPILOT_PROFILE||(env.NODE_ENV==="production"?null:"prototype");
 if(!["prototype","protected"].includes(mode))throw new Error("Explicit PROFITPILOT_PROFILE required");
 enforceProtectedImageProfile(mode,existsSync("/usr/local/bin/profitpilot-scan"));
 const protectedMode=mode==="protected";
 if(protectedMode&&env.NODE_ENV!=="production")
  throw Error("Protected profile requires NODE_ENV=production");
 // Node's global override can disable HTTPS certificate verification,
 // including remote identity JWKS. Fail before any network or secret access.
 if(protectedMode&&env.NODE_TLS_REJECT_UNAUTHORIZED==="0")
  throw Error("Protected profile forbids disabling TLS certificate verification");
 const corsOrigins=protectedMode?protectedCorsOrigins(env.CORS_ORIGIN):
  (env.CORS_ORIGIN||"").split(",").map(x=>x.trim()).filter(Boolean);
 const scannerEnabled=env.MALWARE_SCAN_MODE==="clamav";
 const acr=env.AUTH_MFA_ACR||null;
 if(protectedMode&&(!scannerEnabled||!acr||acr.length>200||env.DATABASE_SSL!=="true"||!env.DATABASE_URL_FILE||!env.TENANT_CONTEXT_HMAC_SECRET_FILE))
  throw new Error("Protected profile requires database TLS, mounted secrets, scanner and trusted MFA claim");
 return {mode,protectedMode,scannerEnabled,acr,corsOrigins};
}
// Only owner-controlled files and directory paths are accepted in protected mode.
// lstat of every ancestor blocks symlinked mounts; O_NOFOLLOW and descriptor
// identity checks prevent a final-component symlink or a swapped file being read.
// These are local filesystem checks, not a substitute for immutable read-only mounts.
function inspectProtectedSecretPath(path,name){
 if(typeof path!=="string"||path.length<2||path.length>4096||
   path.includes("\0")||!isAbsolute(path)||resolve(path)!==path||
   !Number.isInteger(constants.O_NOFOLLOW)||constants.O_NOFOLLOW===0)
  throw Error("Protected mounted secret requires an absolute, normalised, non-symlink path: "+name);
 const {root}=parse(path);
 const relative=path.slice(root.length).split(sep);
 if(relative.some(part=>!part||part==="."||part===".."))
  throw Error("Invalid protected mounted secret path: "+name);
 const effectiveUid=typeof process.geteuid==="function"?process.geteuid():null;
 if(!Number.isInteger(effectiveUid))
  throw Error("Protected mounted secrets require POSIX ownership checks: "+name);
 let current=root;
 const rootStat=lstatSync(root);
 const parents=[rootStat];
 for(const component of relative.slice(0,-1)){
  current=join(current,component);
  parents.push(lstatSync(current));
 }
 for(const stat of parents){
  if(!stat.isDirectory()||stat.isSymbolicLink()||
    (stat.uid!==0&&stat.uid!==effectiveUid))
   throw Error("Untrusted protected secret directory or symlink: "+name);
  // /tmp (root-owned + sticky) is allowed for isolated synthetic CI fixtures.
  // Any other writable ancestor lets another user swap secret path components.
  const rootSticky=stat.uid===0&&(stat.mode&0o1000)!==0;
  if((stat.mode&0o022)!==0&&!rootSticky)
   throw Error("Writable protected secret ancestor directory: "+name);
 }
 const leaf=lstatSync(path);
 if(!leaf.isFile()||leaf.isSymbolicLink()||(leaf.mode&0o7000)!==0||
   ((leaf.mode&0o777)!==0o400&&(leaf.mode&0o777)!==0o600))
  throw Error("Protected mounted secret must have owner-only permissions and regular file type: "+name);
 if(leaf.uid!==effectiveUid||leaf.nlink!==1)
  throw Error("Protected mounted secret ownership or hardlink count is unsafe: "+name);
 return leaf;
}
function equalFileIdentity(left,right){
 return left.dev===right.dev&&left.ino===right.ino&&
   left.uid===right.uid&&left.gid===right.gid&&
   left.mode===right.mode&&left.nlink===right.nlink&&
   left.size===right.size&&left.mtimeMs===right.mtimeMs&&
   left.ctimeMs===right.ctimeMs;
}
export function readSecret(name,env=process.env){
 const profile=deploymentProfile(env);
 const path=env[name+"_FILE"];
 if(path!==undefined&&path!==null&&path!==""){
  const protectedMode=profile.protectedMode;
  // Preserve prototype legacy semantics for a blank direct setting, but
  // protected mode refuses even an empty direct-secret environment variable.
  if(protectedMode?Object.hasOwn(env,name):Boolean(env[name]))
   throw new Error("Ambiguous secret configuration: "+name);
  let fd;
  try{
   const initial=protectedMode?inspectProtectedSecretPath(path,name):null;
   // O_NONBLOCK avoids a malicious FIFO stalling process start. O_NOFOLLOW
   // rejects final symlinks even in prototype/test profiles.
   fd=openSync(path,constants.O_RDONLY|constants.O_NONBLOCK|constants.O_NOFOLLOW);
   const before=fstatSync(fd);
   if(!before.isFile()||before.size<1||before.size>8192)
    throw new Error("Invalid mounted secret: "+name);
   if(protectedMode&&!equalFileIdentity(initial,before))
    throw Error("Protected mounted secret changed before read: "+name);
   const bytes=Buffer.alloc(8193);let offset=0;
   while(offset<bytes.length){
    const n=readSync(fd,bytes,offset,bytes.length-offset,null);
    if(n===0)break;
    offset+=n;
   }
   if(offset<1||offset>8192)throw new Error("Invalid mounted secret: "+name);
   const after=fstatSync(fd);
   if(protectedMode&&(!equalFileIdentity(before,after)||
      !equalFileIdentity(after,inspectProtectedSecretPath(path,name))))
    throw Error("Protected mounted secret changed during read: "+name);
   const decoded=new TextDecoder("utf-8",{fatal:true}).decode(bytes.subarray(0,offset));
   // Secrets may have a single final newline from a standard secret manager,
   // but never silently normalise whitespace or accept embedded control data.
   const value=protectedMode?decoded.replace(/\r?\n$/,""):decoded.trim();
   if(protectedMode&&(value!==value.trim()||/[\x00-\x1f\x7f]/.test(value)))
    throw Error("Protected mounted secret contains unsafe whitespace or controls: "+name);
   if(!value)throw new Error("Empty mounted secret: "+name);
   return value;
  }catch(error){
   // Native fs errors include full mount paths in their message. Expose only
   // the safe logical secret name when protected startup fails.
   if(protectedMode&&typeof error?.code==="string"&&
      /^E(?:ACCES|NOENT|LOOP|NOTDIR|PERM|ISDIR|AGAIN|NAMETOOLONG|BADF)$/.test(error.code))
    throw Error("Protected mounted secret filesystem access denied: "+name);
   throw error;
  }finally{if(fd!==undefined)closeSync(fd);}
 }
 if(profile.protectedMode)
  throw Error("Protected secret must be supplied through mounted file: "+name);
 return env[name]||"";
}
export function databaseConfig(env=process.env){
 const profile=deploymentProfile(env),connectionString=readSecret("DATABASE_URL",env);
 if(profile.protectedMode){
  // WHATWG URL errors include an enumerable .input containing the full
  // database URL (including credentials). Never propagate that exception to
  // unhandled startup logs or API error handlers.
  let url;
  try{url=new URL(connectionString);}
  catch{throw new Error("Protected database URL is invalid");}
  if(!["postgres:","postgresql:"].includes(url.protocol)||!url.hostname||!url.pathname||url.pathname==="/"||url.hash||url.search)
   throw new Error("Protected database URL requires a host/database and no query or fragment overrides");
 }
 return {connectionString,ssl:env.DATABASE_SSL==="true"?{rejectUnauthorized:true}:false};
}
// Must run before binding an HTTP listener. Does not contact external services
// or prove live provider availability; protected deployment still needs review.
export function protectedStartupPreflight(env=process.env){
 const profile=deploymentProfile(env);
 if(!profile.protectedMode)throw Error("Protected startup preflight requires protected profile");
 databaseConfig(env);
 const secret=readSecret("TENANT_CONTEXT_HMAC_SECRET",env);
 if(!/^(?:[a-f0-9]{2}){32,}$/i.test(secret))
  throw Error("Invalid mounted tenant-context signing key");
 return Object.freeze({profile:"protected",mountedSecretsVerified:true,
  externalCustodyVerified:false,liveInfrastructureVerified:false,
  productionReleaseApproved:false});
}
export function validMfa(payload,requiredAcr,nowSeconds,maxAgeSeconds){
 if(!requiredAcr)return true;
 return payload.acr===requiredAcr&&Number.isSafeInteger(payload.auth_time)&&payload.auth_time>0&&payload.auth_time<=nowSeconds+5&&nowSeconds-payload.auth_time<=maxAgeSeconds;
}
