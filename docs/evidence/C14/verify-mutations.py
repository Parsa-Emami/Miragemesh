from pathlib import Path
import subprocess,json,os
root=Path(__file__).resolve().parents[3];p=root/'internal/sensor/event.go';original=p.read_text()
cases=[('quota', 'if count >= document.Settings.SpoolLimitEvents {','if count >= document.Settings.SpoolLimitEvents && false {','TestSpoolDurableBoundedReplayAndRestart'),('replay','if replay {','if false {','TestSpoolDurableBoundedReplayAndRestart'),('signature','latest, err := applier.project(ctx, records)','latest := make(map[string]storage.Record)\nfor _, r := range records { if r.Config != nil { d, _ := config.Parse(r.Config.Payload); latest[d.SensorID] = r } }\nvar err error','TestSpoolRejectsForgedAppliedConfiguration')]
for name,old,new,test in cases:
 try:
  assert old in original;p.write_text(original.replace(old,new,1))
  r=subprocess.run(['python3',str(root/'docs/evidence/C14/run.py'),'mutation-'+name,'go','test','./tests','-count=1','-run','^'+test+'$'],cwd=root)
  assert r.returncode!=0,'mutation escaped: '+name
  log=(root/('docs/evidence/C14/mutation-'+name+'.log')).read_text()
  assert '--- FAIL: '+test in log and '[build failed]' not in log, 'not a behavioral failure: '+name
 finally:p.write_text(original)
print('Three behavioral mutations caught; production source restored byte-for-byte.')
