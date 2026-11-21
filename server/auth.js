import {createRemoteJWKSet,jwtVerify} from "jose";
import {isIP} from "node:net";
import {deploymentProfile,validMfa} from "./deployment.js";
let jwks,jwksUrl;
export function identityConfig(env=process.env){
 const {AUTH_ISSUER,AUTH_AUDIENCE,AUTH_JWKS_URL}=env;
 if(typeof AUTH_ISSUER!=="string"||typeof AUTH_JWKS_URL!=="string"||
   typeof AUTH_AUDIENCE!=="string"||AUTH_AUDIENCE.length<1||AUTH_AUDIENCE.length>256||
   AUTH_AUDIENCE!==AUTH_AUDIENCE.trim()||/[\x00-\x1f\x7f]/.test(AUTH_AUDIENCE)||
   AUTH_ISSUER.length>2048||AUTH_JWKS_URL.length>2048)
  throw new Error("Authentication is not configured");
 // WHATWG URL parse failures expose the original .input property (including
 // accidental credentials). Protected startup runs outside HTTP error handlers;
 // never let the parser's exception reach stdout/stderr or structured logs.
 let url,issuer;
 try{
  url=new URL(AUTH_JWKS_URL);
  issuer=new URL(AUTH_ISSUER);
 }catch{
  throw new Error("Invalid authentication configuration");
 }
 const protectedMode=env.PROFITPILOT_PROFILE==="protected";
 const localTest=env.NODE_ENV==="test"&&!protectedMode&&url.protocol==="http:"&&["127.0.0.1","[::1]","localhost"].includes(url.hostname);
 if((url.protocol!=="https:"&&!localTest)||url.username||url.password||url.hash||
 issuer.protocol!=="https:"||issuer.username||issuer.password||issuer.hash)
  throw new Error("Invalid authentication configuration");
 // Refuse explicitly local/IP literal identity endpoints in protected mode.
 // Hostname checks do NOT substitute for an outbound egress policy or DNS pinning.
 const internalHost=h=>{
  const n=h.replace(/^\[|\]$/g,"").toLowerCase();
  return isIP(n)!==0||n==="localhost"||n.endsWith(".localhost")||
   n.endsWith(".local")||n==="0.0.0.0";
 };
 if(protectedMode&&(internalHost(url.hostname)||internalHost(issuer.hostname)))
  throw new Error("Protected identity endpoints require trusted nonlocal DNS hosts");
 return {issuer:AUTH_ISSUER,audience:AUTH_AUDIENCE,url};
}
export const validSubject=value=>typeof value==="string"&&value.length>0&&value.length<=255&&value===value.trim()&&!/[\x00-\x1f\x7f-\x9f]/u.test(value);
export const validTokenLifetime=payload=>Number.isSafeInteger(payload.iat)&&Number.isSafeInteger(payload.exp)&&payload.exp>payload.iat&&payload.exp-payload.iat<=3600;
export function authRequired(){
 return async(req,res,next)=>{
  const token=req.headers.authorization?.match(/^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i)?.[1];
  if(!token||token.length>8192)return res.status(401).json({error:"Authentication required"});
  let c;
  try{c=identityConfig();}catch{return res.status(503).json({error:"Authentication unavailable"});}
  try{
   if(!jwks||jwksUrl!==c.url.href){jwks=createRemoteJWKSet(c.url,{timeoutDuration:5000,cooldownDuration:30000});jwksUrl=c.url.href;}
   const {payload}=await jwtVerify(token,jwks,{issuer:c.issuer,audience:c.audience,algorithms:["RS256","ES256"],requiredClaims:["sub","iat","exp"],maxTokenAge:3600,clockTolerance:5});
   if(!validSubject(payload.sub)||!validTokenLifetime(payload))return res.status(401).json({error:"Invalid identity or token lifetime"});
   const profile=deploymentProfile();
   if(!validMfa(payload,profile.acr,Math.floor(Date.now()/1000),["GET","HEAD"].includes(req.method)?43200:900))
    return res.status(403).json({error:"Verified recent multi-factor authentication required"});
   req.identity={subject:payload.sub,email:typeof payload.email==="string"&&payload.email.length<=320?payload.email:null};
   next();
  }catch{res.status(401).json({error:"Invalid or expired access token"});}
 };
}
export function requireRole(...roles){
 return (req,res,next)=>{if(!req.membership||!roles.includes(req.membership.role))return res.status(403).json({error:"Insufficient tenant role"});next();};
}
