import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { once } from 'node:events';
const trace='/tmp/miragemesh-c03-network.trace';
const proc=spawn('strace',['-f','-e','trace=connect','-o',trace,process.execPath,'scripts/start-local.mjs','--port','0'],{stdio:['ignore','pipe','pipe']});
let ready;
const stopped=once(proc,'exit');
try {
 ready=await new Promise((accept,reject)=>{
  let text=''; const timer=setTimeout(()=>reject(new Error('trace startup deadline')),10000);
  proc.stdout.on('data',bytes=>{text+=bytes;if(text.includes('\n')){clearTimeout(timer);accept(JSON.parse(text.split('\n')[0]));}});
  proc.once('error',reject); stopped.then(()=>{clearTimeout(timer);reject(new Error('trace exited'));});
 });
 const base=`http://127.0.0.1:${ready.port}`;
 if(!(await fetch(base+'/api/engine/health')).ok)throw new Error('health failed');
 // strace is not the owner; signal the observed supervisor, which owns its Go child.
 const ps=spawn('pgrep',['-P',String(proc.pid)],{stdio:['ignore','pipe','inherit']});let pid='';for await(const bytes of ps.stdout)pid+=bytes;
 const supervisor=Number(pid.trim());if(!supervisor)throw new Error('supervisor not found');process.kill(supervisor,'SIGTERM');
 await stopped;
 const events=(await readFile(trace,'utf8')).split('\n').filter(line=>line.includes('connect('));
 const network=events.filter(line=>line.includes('AF_INET'));
 if(network.some(line=>!line.includes('127.0.0.1')))throw new Error('non-loopback network connect detected');
 console.log(JSON.stringify({passed:true,observed_network_connects:network.length,destinations:'127.0.0.1 only',scope:'traced C03 startup and runtime health; no provider/decoy isolation certified'}));
}finally{if(proc.exitCode===null&&proc.signalCode===null)proc.kill('SIGTERM');}
