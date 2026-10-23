import { test, expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startLocal } from '../../../scripts/start-local.mjs';

const execute=promisify(execFile);
const common=(dir:string)=>['--verify-update','--update-state-dir',join(dir,'state'),'--update-publisher-key-file',join(dir,'publisher.pub'),'--update-recovery-key-file',join(dir,'recovery.pub'),'--update-platform','linux/amd64','--update-max-operations','128','--update-max-bytes','2097152','--update-max-manifest-bytes','131072','--update-max-sensors','16','--update-max-artifact-bytes','1048576','--update-max-metadata-ttl-seconds','3600','--update-max-recovery-ttl-seconds','600'];

test('real update authority and scoped recovery survive restart with accessible evidence at 360px',async({page},testInfo)=>{
 const dir=await mkdtemp(join(tmpdir(),'miragemesh-c25-browser-'));let running:Awaited<ReturnType<typeof startLocal>>|undefined;const external:string[]=[];
 page.on('request',request=>{if(!request.url().startsWith('http://127.0.0.1:'))external.push(request.url());});
 const updateStatus={stateDir:join(dir,'state'),publisherKeyFile:join(dir,'publisher.pub'),recoveryKeyFile:join(dir,'recovery.pub'),platform:'linux/amd64',maxOperations:128,maxBytes:2097152,maxManifestBytes:131072,maxSensors:16,maxArtifactBytes:1048576,maxMetadataTTLSeconds:3600,maxRecoveryTTLSeconds:600};
 try{
  await execute('go',['run','./tests/fixtures/miragemesh/C25/seed',dir],{timeout:30000});running=await startLocal({port:0,updateStatus});
  await page.setViewportSize({width:360,height:800});await page.goto(`http://127.0.0.1:${running.server.address().port}/#updates`);
  const region=page.getByRole('region',{name:'Update verification'});await expect(region).toContainText('Verified release 4');await expect(region).toContainText('Highest verified release 4');
  await region.locator('summary').focus();await page.keyboard.press('Enter');await expect(region.locator('details')).toHaveAttribute('open','');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:testInfo.outputPath('updates-mobile.png'),fullPage:true});
  const response=await page.request.get(`http://127.0.0.1:${running.server.address().port}/api/v1/updates`);const raw=await response.text();expect(raw).not.toContain('signature');expect(raw).not.toContain('payload');
  await running.close();running=undefined;
  await execute('dist/engine/miragemesh',[...common(dir),'--update-action','accept-metadata','--update-metadata-file',join(dir,'metadata-2.json'),'--update-signature-file',join(dir,'metadata-2.sig')]);
  running=await startLocal({port:0,updateStatus});await page.goto(`http://127.0.0.1:${running.server.address().port}/#updates`);await expect(region).toContainText('Revoked release');await expect(region).toContainText('Metadata revision 2');await running.close();running=undefined;
  await execute('dist/engine/miragemesh',[...common(dir),'--update-action','verify','--update-sensor','sensor-25','--update-version','2','--update-artifact-file',join(dir,'release-2.bin'),'--update-grant-file',join(dir,'grant.json'),'--update-grant-signature-file',join(dir,'grant.sig')]);
  for(let i=0;i<2;i++){running=await startLocal({port:0,updateStatus});await page.goto(`http://127.0.0.1:${running.server.address().port}/#updates`);await expect(region).toContainText('Verified release 2');await expect(region).toContainText('Highest verified release 4');await expect(region).toContainText('Signed recovery used');await running.close();running=undefined;}
  expect(external).toEqual([]);
 }finally{if(running)await running.close();await rm(dir,{recursive:true,force:true});}
});

test('update read failures retain stale evidence and untrusted strings stay inert',async({page})=>{
 let fail=false;const value={schema_version:'1',platform:'linux/amd64',publisher_fingerprint:'a'.repeat(64),recovery_fingerprint:'b'.repeat(64),observed_at:'2026-01-01T00:00:00Z',sensors:[{sensor_id:'<img src=x onerror=globalThis.c25Sentinel=1>',revision:1,issued_at:'2026-01-01T00:00:00Z',expires_at:'2026-01-01T01:00:00Z',metadata_digest:'c'.repeat(64),releases:[{version:4,sha256:'d'.repeat(64),length:100}],revoked_versions:[3],version:4,high_water_version:4,verified_revision:1,verified_at:'2026-01-01T00:00:00Z',recovery:false,status:'verified'}]};
 await page.route('**/api/v1/updates',route=>fail?route.abort('failed'):route.fulfill({json:value}));await page.goto('/#updates');const region=page.getByRole('region',{name:'Update verification'});await expect(region).toContainText(value.sensors[0].sensor_id);await expect(page.locator('main img,main script')).toHaveCount(0);expect(await page.evaluate(()=>(globalThis as Record<string,unknown>).c25Sentinel)).toBeUndefined();
 fail=true;await page.getByRole('button',{name:'Refresh updates'}).click();await expect(page.getByRole('alert')).toContainText('stale');await expect(region).toContainText('Verified release 4');
 fail=false;value.sensors[0].status='revoked';await page.getByRole('button',{name:'Refresh updates'}).click();await expect(page.getByRole('alert')).toContainText('invalid');await expect(region).toContainText('Verified release 4');
});

test('update page explains unavailable authority without claiming verification',async({page})=>{
 await page.goto('/#updates');await expect(page.getByRole('heading',{name:'Signed sensor updates.'})).toBeVisible();await expect(page.getByRole('alert')).toContainText('unavailable');await expect(page.getByRole('region',{name:'Update verification'})).toHaveCount(0);
});
