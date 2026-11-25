import test from 'node:test';
import assert from 'node:assert/strict';
import { randomInt, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
const base=process.env.MMS_API_URL||'http://127.0.0.1:3002';
const db=process.env.MMS_TEST_DB_CONTAINER||'mms-vehicle-test-db-1';
function sql(query){
 assert.equal(execFileSync('docker',['exec',db,'psql','-U','mms_test','-d','mms_test','-At','-c','SELECT current_database()'],{encoding:'utf8'}).trim(),'mms_test');
 return execFileSync('docker',['exec',db,'psql','-U','mms_test','-d','mms_test','-At','-v','ON_ERROR_STOP=1','-c',query],{encoding:'utf8'}).trim();
}
async function api(path,{token,method='GET',body,raw}={}){
 const r=await fetch(`${base}/api${path}`,{method,headers:{...(token?{Authorization:`Bearer ${token}`}:{ }),...(raw?{'Content-Type':'image/png'}:body?{'Content-Type':'application/json'}:{})},body:raw||(body?JSON.stringify(body):undefined)});
 const str=await r.text();let data;try{data=JSON.parse(str);}catch{data=str;}return{status:r.status,data};
}
async function customer(){const suffix=randomInt(1000000,8000000);const r=await api('/auth/customer-register',{method:'POST',body:{firstName:'Garage',lastName:'Recette',phone:`+26137${suffix}`,email:`garage-${randomUUID()}@example.mg`,password:'GarageRecette-2026'}});assert.equal(r.status,201);return{id:r.data.user.user.id,token:r.data.accessToken};}
const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC','base64');

test('suppression de moto : propriété, carnet, photos et historique',async t=>{
 assert.equal((await api('/health')).data.mode,'test','Never run this suite against production');
 const a=await customer(),b=await customer();const vehiclePath=id=>`/customers/${a.id}/vehicles/${id}`;
 async function vehicle(){const r=await api(`/customers/${a.id}/vehicles`,{method:'POST',token:a.token,body:{name:'Gasgas',model:'EC',plate:'',displacementCc:250,year:2024}});assert.equal(r.status,201);return r.data;}
 const v=await vehicle();const other=await vehicle();
 assert.equal((await api(`${vehiclePath(v.id)}/photo`,{method:'PUT',token:a.token,raw:png})).status,200);
 sql(`INSERT INTO maintenance(id,customer_id,vehicle_id,title,maintenance_date,note) VALUES('${randomUUID()}','${a.id}','${v.id}','Vidange',CURRENT_DATE,'Huile remplacée'),('${randomUUID()}','${a.id}','${other.id}','Freins',CURRENT_DATE,'À conserver')`);
 await t.test('un autre client ne peut pas supprimer la moto',async()=>{
  assert.equal((await api(vehiclePath(v.id),{method:'DELETE',token:b.token})).status,403);
  assert.equal((await api(`/customers/${b.id}/vehicles/${v.id}`,{method:'DELETE',token:b.token})).status,404);
  assert.equal(sql(`SELECT count(*) FROM maintenance WHERE vehicle_id='${v.id}'`),'1');
 });
 await t.test('suppression effective du carnet et de la photo sans toucher à l’autre moto',async()=>{
  assert.equal((await api(vehiclePath(v.id),{method:'DELETE',token:a.token})).status,200);
  assert.equal(sql(`SELECT count(*) FROM vehicles WHERE id='${v.id}'`),'0');
  assert.equal(sql(`SELECT count(*) FROM maintenance WHERE vehicle_id='${v.id}'`),'0');
  assert.equal(sql(`SELECT count(*) FROM vehicle_photos WHERE vehicle_id='${v.id}'`),'0');
  assert.equal(sql(`SELECT count(*) FROM maintenance WHERE vehicle_id='${other.id}'`),'1');
  assert.equal((await api(`${vehiclePath(v.id)}/photo`,{token:a.token})).status,404);
  assert.equal((await api(vehiclePath(v.id),{method:'PATCH',token:a.token,body:{name:'Retour',displacementCc:250,year:2024}})).status,404);
  assert.equal((await api(`${vehiclePath(v.id)}/photo`,{method:'PUT',token:a.token,raw:png})).status,404);
 });
 await t.test('deux suppressions simultanées restent atomiques',async()=>{
  const concurrent=await vehicle();
  const results=await Promise.all([api(vehiclePath(concurrent.id),{method:'DELETE',token:a.token}),api(vehiclePath(concurrent.id),{method:'DELETE',token:a.token})]);
  assert.deepEqual(results.map(r=>r.status).sort(),[200,404]);
 });
 const active=await vehicle();
 const booking=await api(`/customers/${a.id}/appointments`,{method:'POST',token:a.token,body:{vehicleId:active.id,problem:'Le moteur ne démarre plus depuis hier.',diagnosis:'',kind:'Urgence',address:'Adresse de recette locale',contactPhone:'0341234567',immobilized:true}});
 assert.equal(booking.status,201);
 await t.test('refus sans perte de données si une demande est en cours',async()=>{
  assert.equal((await api(vehiclePath(active.id),{method:'DELETE',token:a.token})).status,409);
  assert.equal(sql(`SELECT count(*) FROM vehicles WHERE id='${active.id}' AND deleted_at IS NULL`),'1');
 });
 await t.test('une demande clôturée et son audit restent consultables après retrait',async()=>{
  const cancel=await api(`/customers/${a.id}/appointments/${booking.data.id}/cancel`,{method:'PATCH',token:a.token,body:{}});assert.equal(cancel.status,200);
  assert.equal((await api(vehiclePath(active.id),{method:'DELETE',token:a.token})).status,200);
  assert.equal(sql(`SELECT count(*) FROM vehicles WHERE id='${active.id}' AND deleted_at IS NOT NULL`),'1');
  assert.equal(sql(`SELECT count(*) FROM ticket_events WHERE ticket_id='${booking.data.ticket.id}'`),'2');
  assert.equal((await api(`/customers/${a.id}/tickets/${booking.data.ticket.reference}`,{token:a.token})).status,200);
  const profile=await api('/auth/me',{token:a.token});assert.ok(!profile.data.vehicles.some(v=>v.id===active.id));
  const again=await api(`/customers/${a.id}/appointments`,{method:'POST',token:a.token,body:{vehicleId:active.id}});assert.equal(again.status,400);
  assert.equal((await api(vehiclePath(active.id),{method:'DELETE',token:a.token})).status,404);
  assert.equal(sql("SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled<>'O'"),'0');
 });
});
