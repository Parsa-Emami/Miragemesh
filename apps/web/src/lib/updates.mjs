const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const fields=(value,allowed)=>object(value)&&Object.keys(value).every(key=>allowed.includes(key));
const integer=value=>Number.isSafeInteger(value)&&value>=0;
const positive=value=>integer(value)&&value>0;
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const fail=()=>{throw new Error('Update response is invalid.');};

function instant(value){
 if(typeof value!=='string')return null;
 const match=/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
 if(!match||Number(value.slice(0,4))<1000)return null;
 const ms=Date.parse(match[1]+'Z');if(!Number.isFinite(ms)||new Date(ms).toISOString().slice(0,19)!==match[1])return null;
 return BigInt(ms)*1000000n+BigInt((match[2]??'').padEnd(9,'0'));
}

export function validateUpdateSnapshot(value){
 if(!fields(value,['schema_version','platform','publisher_fingerprint','recovery_fingerprint','observed_at','sensors'])||value.schema_version!=='1'||typeof value.platform!=='string'||!/^[a-z0-9]{1,16}\/[a-z0-9]{1,16}$/.test(value.platform)||!digest(value.publisher_fingerprint)||!digest(value.recovery_fingerprint)||value.publisher_fingerprint===value.recovery_fingerprint||!Array.isArray(value.sensors)||value.sensors.length>8192)fail();
 const now=instant(value.observed_at);if(now===null)fail();const sensors=new Set();
 for(const s of value.sensors){
  if(!fields(s,['sensor_id','revision','issued_at','expires_at','metadata_digest','revoked_versions','releases','version','high_water_version','verified_revision','verified_at','recovery','status'])||typeof s.sensor_id!=='string'||!s.sensor_id.isWellFormed()||Array.from(s.sensor_id).length<1||Array.from(s.sensor_id).length>128||sensors.has(s.sensor_id)||!positive(s.revision)||!digest(s.metadata_digest)||!integer(s.version)||!integer(s.high_water_version)||s.high_water_version<s.version||!integer(s.verified_revision)||s.verified_revision>s.revision||typeof s.recovery!=='boolean'||!Array.isArray(s.releases)||s.releases.length>16||!Array.isArray(s.revoked_versions)||s.revoked_versions.length>64)fail();
  sensors.add(s.sensor_id);const issued=instant(s.issued_at),expiry=instant(s.expires_at);if(issued===null||expiry===null||issued>=expiry)fail();
  const releases=new Set();for(const r of s.releases){if(!fields(r,['version','sha256','length'])||!positive(r.version)||releases.has(r.version)||!digest(r.sha256)||!positive(r.length)||r.length>67108864)fail();releases.add(r.version);}
  const revoked=new Set();for(const n of s.revoked_versions){if(!positive(n)||revoked.has(n))fail();revoked.add(n);}
  if(s.version===0){if(s.high_water_version!==0||s.verified_revision!==0||s.verified_at!==undefined||s.recovery)fail();}
  else if(s.verified_revision===0||instant(s.verified_at)===null||s.recovery!==(s.version<s.high_water_version))fail();
  const expected=now<issued||now>=expiry?'expired':s.version===0?'no_candidate':revoked.has(s.version)?'revoked':s.verified_revision!==s.revision?'authority_changed':'verified';
  if(s.status!==expected||expected==='verified'&&!releases.has(s.version))fail();
 }
 return value;
}
