import { useCallback, useEffect, useRef, useState } from 'react';
import { validateUpdateSnapshot } from '../lib/updates.mjs';

type Release={version:number;sha256:string;length:number};
type Sensor={sensor_id:string;revision:number;issued_at:string;expires_at:string;metadata_digest:string;revoked_versions:number[];releases:Release[];version:number;high_water_version:number;verified_revision:number;verified_at?:string;recovery:boolean;status:'verified'|'no_candidate'|'expired'|'revoked'|'authority_changed'};
type Snapshot={platform:string;publisher_fingerprint:string;recovery_fingerprint:string;observed_at:string;sensors:Sensor[]};

export default function Updates(){
 const [snapshot,setSnapshot]=useState<Snapshot|null>(null),[loading,setLoading]=useState(true),[error,setError]=useState('');const active=useRef<AbortController|null>(null);
 const refresh=useCallback(async()=>{
  active.current?.abort();const controller=new AbortController();active.current=controller;setLoading(true);
  try{
   const response=await fetch('/api/v1/updates',{cache:'no-store',credentials:'omit',signal:AbortSignal.any([controller.signal,AbortSignal.timeout(3000)])});
   if(!response.ok)throw new Error('Update status is unavailable. Check the local engine and update trust configuration.');
   let value:Snapshot;try{value=validateUpdateSnapshot(await response.json()) as Snapshot;}catch{throw new Error('Update response is invalid. No new snapshot was accepted.');}
   if(!controller.signal.aborted){setSnapshot(value);setError('');}
  }catch(cause){if(!controller.signal.aborted)setError(cause instanceof Error&&cause.name==='Error'?cause.message:'Update status request was interrupted or timed out. Retry the read.');}
  finally{if(!controller.signal.aborted)setLoading(false);}
 },[]);
 useEffect(()=>{void refresh();return()=>active.current?.abort();},[refresh]);
 return <div className="certificate-workspace">
  <div className="incident-toolbar"><p className="muted">{snapshot?<>Last checked: <time dateTime={snapshot.observed_at}>{snapshot.observed_at}</time>{error?' · Stale snapshot':''}</>:'Local signed update authority'}</p><button onClick={()=>void refresh()} disabled={loading}>{loading?'Loading updates…':'Refresh updates'}</button></div>
  {error&&<p role="alert" className="error">{snapshot?'Displayed update evidence is stale. ':''}{error}</p>}
  {!snapshot&&loading&&<p role="status">Loading update evidence…</p>}
  {snapshot&&<section aria-label="Update verification"><h2>Sensor update evidence</h2><p>Signature and local file verification do not confirm installation or a running sensor version.</p><p className="muted">Platform: {snapshot.platform}. The local operator supplies signed metadata and candidate files.</p>
   {snapshot.sensors.length===0?<div className="panel"><p>No signed update metadata has been accepted.</p></div>:snapshot.sensors.map(s=><article key={s.sensor_id} className="panel certificate-sensor">
    <div className="eyebrow">Metadata revision {s.revision}</div><h3><code>{s.sensor_id}</code></h3>
    <span className={'state '+s.status}>{s.status==='verified'?`Verified release ${s.version}`:s.status==='revoked'?'Revoked release':s.status==='expired'?'Expired authority':s.status==='authority_changed'?'Verification needs renewal':'Awaiting a candidate file'}</span>
    <p>Authority expires <time dateTime={s.expires_at}>{s.expires_at}</time>.</p>
    {s.version>0&&<p>Last verified release {s.version} · Highest verified release {s.high_water_version}.{s.verified_at&&<> Checked <time dateTime={s.verified_at}>{s.verified_at}</time>.</>}</p>}
    {s.recovery&&<p>Signed recovery used. The highest verified release remains {s.high_water_version}.</p>}
    {s.status==='revoked'&&<p>This release is blocked by the current signed authority. Choose an allowed release; a recovery grant cannot override revocation.</p>}
    {s.status==='expired'&&<p>Fresh signed metadata is required before any candidate can be trusted.</p>}
    {s.status==='authority_changed'&&<p>The authority changed after the last file check. Verify the candidate against the current metadata.</p>}
    <p>Revoked releases: {s.revoked_versions.length?s.revoked_versions.join(', '):'None recorded'}. Returning below the highest verified release requires a scoped, expiring recovery signature.</p>
    <details><summary>Update evidence details</summary><dl className="source-trace"><dt>Metadata SHA-256</dt><dd><code>{s.metadata_digest}</code></dd><dt>Publisher key SHA-256</dt><dd><code>{snapshot.publisher_fingerprint}</code></dd><dt>Recovery key SHA-256</dt><dd><code>{snapshot.recovery_fingerprint}</code></dd></dl><h4>Signed release files</h4>{s.releases.length===0?<p>No release files are currently offered.</p>:s.releases.map(r=><p key={r.version}>Release {r.version} · {r.length} bytes<br/><code>{r.sha256}</code></p>)}</details>
   </article>)}
  </section>}
 </div>;
}
