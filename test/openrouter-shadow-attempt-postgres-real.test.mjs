// Ephemeral PostgreSQL16: synthetic durable attempt tombstones, no model calls.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';

const sql=readFileSync(new URL(
  '../sql/reviewer_b_attempt_tombstone_synthetic_v1.sql',import.meta.url),'utf8');
const HEAD='a'.repeat(40),PASS='synthetic-shadow-ci-only-20261020';
const makeClient=(Client,user='postgres',password=PASS)=>new Client({
  host:'127.0.0.1',port:5432,database:'postgres',user,password,
  connectionTimeoutMillis:2500,query_timeout:4000,
});
const query=(c,fn,params)=>c.query(
  'SELECT * FROM reviewer_b_attempt_shadow.'+fn+'('+
  params.map((_,i)=>'$'+(i+1)).join(',')+')',params);
function blockedResult(result,recorded){
  assert.equal(result.rows.length,1);
  const row=result.rows[0];
  assert.equal(row.may_spend,false);
  assert.equal(row.may_dispatch,false);
  assert.equal(row.recorded,recorded);
}
test('real PostgreSQL16: durable synthetic risk tombstone, no retry or privilege escalation',{
  skip:process.env.SHADOW_POSTGRES_REAL!=='1'||!process.env.SHADOW_PG_CLIENT_ENTRY?
    'isolated GitHub Actions Postgres16 required':false,
  timeout:60000,
},async t=>{
  assert.equal(process.env.PGHOST,'127.0.0.1');
  assert.equal(process.env.PGPASSWORD,PASS);
  const mod=await import(pathToFileURL(process.env.SHADOW_PG_CLIENT_ENTRY).href);
  const Client=mod.default?.Client||mod.Client;
  const admin=makeClient(Client),writer=makeClient(Client,'attempt_shadow_ci_login'),
    observer=makeClient(Client),reconnected=makeClient(Client,'attempt_shadow_ci_login');
  t.after(async()=>Promise.all(
    [admin,writer,observer,reconnected].map(c=>c.end().catch(()=>{}))));
  await admin.connect();
  await observer.connect();
  await admin.query(sql);
  const role=await admin.query(
    "SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname='reviewer_b_attempt_invoker_v1'");
  assert.equal(role.rows[0].rolcanlogin,false);
  await admin.query(
    "CREATE ROLE attempt_shadow_ci_login LOGIN INHERIT PASSWORD 'synthetic-shadow-ci-only-20261020'");
  await admin.query('GRANT reviewer_b_attempt_invoker_v1 TO attempt_shadow_ci_login');
  const bad=makeClient(Client,'attempt_shadow_ci_login','synthetic-wrong-password');
  t.after(async()=>bad.end().catch(()=>{}));
  await assert.rejects(()=>bad.connect(),e=>e.code==='28P01');
  await writer.connect();
  await reconnected.connect();

  // No data privileges for untrusted invoker, no owner role membership.
  const privileges=(await writer.query(
    "SELECT has_table_privilege('reviewer_b_attempt_shadow.attempts','SELECT') AS can_read,"+
    " has_table_privilege('reviewer_b_attempt_shadow.attempts','UPDATE') AS can_write,"+
    " has_schema_privilege('reviewer_b_attempt_shadow','CREATE') AS can_create,"+
    " has_function_privilege('reviewer_b_attempt_shadow.record_dispatch_risk(text,text,text)','EXECUTE') AS can_record"
  )).rows[0];
  assert.deepEqual(privileges,{
    can_read:false,can_write:false,can_create:false,can_record:true,
  });
  await assert.rejects(
    ()=>writer.query('SELECT * FROM reviewer_b_attempt_shadow.attempts'),
    e=>e.code==='42501');
  await assert.rejects(
    ()=>writer.query("UPDATE reviewer_b_attempt_shadow.attempts SET status='registered'"),
    e=>e.code==='42501');
  await assert.rejects(
    ()=>writer.query('SET ROLE reviewer_b_attempt_owner_v1'),
    e=>e.code==='42501');

  const call=(client,fn,...args)=>query(client,fn,args);
  const register=(client,req,attempt,role='reviewer_b',head=HEAD)=>
    call(client,'register_synthetic_attempt',req,attempt,role,head);
  const risk=(client,req,attempt,head=HEAD)=>
    call(client,'record_dispatch_risk',req,attempt,head);
  const unknown=(client,req,attempt,head=HEAD)=>
    call(client,'mark_outcome_unknown',req,attempt,head);
  const cancel=(client,req,attempt,head=HEAD)=>
    call(client,'cancel_before_dispatch',req,attempt,head);
  const recover=(client,req,attempt,head=HEAD)=>
    call(client,'observe_attempt_after_uncertain_commit',req,attempt,head);
  const blockedRecovery=(result,found,status=null)=>{
    assert.equal(result.rows.length,1);
    const row=result.rows[0];
    assert.equal(row.identity_found,found);
    assert.equal(row.observed_state,status);
    assert.equal(row.may_spend,false);
    assert.equal(row.may_dispatch,false);
    assert.equal(row.may_retry,false);
  };
  const state=async req=>(await observer.query(
    'SELECT status,dispatch_marker_at,unknown_at,cancelled_at FROM '+
    'reviewer_b_attempt_shadow.attempts WHERE request_id=$1',[req])).rows[0];
  
  blockedResult(await register(writer,'req:1','attempt:1'),true);
  blockedResult(await register(reconnected,'req:1','attempt:2'),false);
  blockedResult(await register(reconnected,'req:2','attempt:1','development'),false);
  blockedResult(await risk(writer,'req:1','wrong-attempt'),false);
  blockedResult(await risk(writer,'req:1','attempt:1','b'.repeat(40)),false);
  assert.equal((await state('req:1')).status,'registered');
  blockedRecovery(await recover(reconnected,'req:1','attempt:1'),
    true,'registered');
  blockedRecovery(await recover(reconnected,'req:1','wrong'),false);
  blockedRecovery(await recover(reconnected,'missing','attempt:1'),false);
  blockedRecovery(await recover(reconnected,'req:1','attempt:1',
    'b'.repeat(40)),false);

  // Real physical connection A holds the target row; separate invoker B
  // must fail immediately via NOWAIT. There is no automated retry.
  await admin.query('BEGIN');
  await admin.query(
    "SELECT request_id FROM reviewer_b_attempt_shadow.attempts WHERE request_id='req:1' FOR UPDATE");
  await assert.rejects(()=>risk(reconnected,'req:1','attempt:1'),
    e=>e.code==='55P03');
  // A read-only recovery observation must also refuse an in-flight write.
  await assert.rejects(()=>recover(reconnected,'req:1','attempt:1'),
    e=>e.code==='55P03');
  await admin.query('ROLLBACK');
  assert.equal((await state('req:1')).status,'registered');

  // Race TWO authenticated invokers for the same prospective dispatch:
  // a transaction holding the tombstone must block the other writer
  // without waiting or performing any hypothetical second dispatch.
  blockedResult(await register(writer,'req:race','attempt:race'),true);
  await writer.query('BEGIN');
  blockedResult(await risk(writer,'req:race','attempt:race'),true);
  assert.equal((await state('req:race')).status,'registered');
  await assert.rejects(
    ()=>risk(reconnected,'req:race','attempt:race'),
    e=>e.code==='55P03');
  await writer.query('COMMIT');
  assert.equal((await state('req:race')).status,
    'dispatch_may_have_occurred');
  blockedResult(await risk(reconnected,'req:race','attempt:race'),false);
  blockedResult(await register(reconnected,'req:race','attempt:other'),false);

  // One committed risk tombstone survives a different backend connection.
  blockedResult(await risk(writer,'req:1','attempt:1'),true);
  const after=await state('req:1');
  assert.equal(after.status,'dispatch_may_have_occurred');
  assert.ok(after.dispatch_marker_at);
  blockedResult(await risk(reconnected,'req:1','attempt:1'),false);
  blockedResult(await register(reconnected,'req:1','attempt:3'),false);
  blockedResult(await cancel(reconnected,'req:1','attempt:1'),false);
  blockedResult(await unknown(reconnected,'req:1','attempt:1'),true);
  assert.equal((await state('req:1')).status,'outcome_unknown');
  blockedResult(await unknown(writer,'req:1','attempt:1'),false);
  blockedResult(await risk(writer,'req:1','attempt:1'),false);

  // Closing and recreating the authenticated physical session does NOT
  // resurrect the request ID in the database.
  await writer.end();
  const restart=makeClient(Client,'attempt_shadow_ci_login');
  t.after(async()=>restart.end().catch(()=>{}));
  await restart.connect();
  blockedResult(await risk(restart,'req:1','attempt:1'),false);
  blockedResult(await register(restart,'req:1','attempt:4'),false);

  // Deterministically simulate transport discarding a successful COMMIT
  // response. This is NOT a real network-fault injection or provider call.
  blockedResult(await register(restart,'req:ack','attempt:ack'),true);
  await restart.query('BEGIN');
  blockedResult(await risk(restart,'req:ack','attempt:ack'),true);
  await assert.rejects(async()=>{
    await restart.query('COMMIT');
    throw Object.assign(new Error('synthetic commit reply lost'),
      {code:'SYNTHETIC_COMMIT_REPLY_LOST'});
  },e=>e.code==='SYNTHETIC_COMMIT_REPLY_LOST');
  const recovery=makeClient(Client,'attempt_shadow_ci_login');
  t.after(async()=>recovery.end().catch(()=>{}));
  await recovery.connect();
  blockedRecovery(await recover(recovery,'req:ack','attempt:ack'),
    true,'dispatch_may_have_occurred');
  blockedResult(await risk(recovery,'req:ack','attempt:ack'),false);
  blockedResult(await register(recovery,'req:ack','attempt:other'),false);
  // A missing row or a REGISTERED row never gives recovery permission to
  // send. A future paid dispatcher would have to remain blocked.
  blockedRecovery(await recover(recovery,'req:unseen','attempt:unseen'),
    false);

  // A cancellation is only possible BEFORE any risk marker exists.
  blockedResult(await register(restart,'req:cancel','attempt:cancel',
    'development'),true);
  blockedResult(await cancel(restart,'req:cancel','attempt:cancel'),true);
  assert.equal((await state('req:cancel')).status,'cancelled_before_dispatch');
  blockedResult(await risk(restart,'req:cancel','attempt:cancel'),false);
  blockedResult(await register(restart,'req:cancel','attempt:new'),false);

  // A test-only rollback discards UNCOMMITTED risk markers. This is
  // precisely why a real network send before COMMIT would be unsafe.
  blockedResult(await register(restart,'req:rollback','attempt:rollback'),true);
  await reconnected.query('BEGIN');
  blockedResult(await risk(reconnected,'req:rollback','attempt:rollback'),true);
  assert.equal((await state('req:rollback')).status,'registered');
  await reconnected.query('ROLLBACK');
  assert.equal((await state('req:rollback')).status,'registered');
  blockedRecovery(await recover(recovery,'req:rollback','attempt:rollback'),
    true,'registered');
  // Recovery is an observation, NOT evidence that an external API request
  // did not occur. The status must never authorize a retry.
  await recovery.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
  blockedRecovery(await recover(recovery,'req:ack','attempt:ack'),false);
  await recovery.query('ROLLBACK');

  // A stale snapshot cannot be used for admission.
  await reconnected.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
  const stale=await register(reconnected,'req:stale','attempt:stale');
  blockedResult(stale,false);
  assert.equal(stale.rows[0].reason,'SHADOW_ATTEMPT_REGISTER_INVALID');
  await reconnected.query('ROLLBACK');

  // No public function EXECUTE or privilege to alter synthetic attempts.
  const grants=await observer.query(
    "SELECT count(*)::int AS n FROM pg_catalog.pg_proc p "+
    "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "+
    "CROSS JOIN LATERAL pg_catalog.aclexplode("+
    "COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a "+
    "WHERE n.nspname='reviewer_b_attempt_shadow' AND a.grantee=0 "+
    "AND a.privilege_type='EXECUTE'");
  assert.equal(grants.rows[0].n,0);
  const count=await observer.query(
    'SELECT count(*)::int AS n FROM reviewer_b_attempt_shadow.attempts');
  assert.equal(count.rows[0].n,5);
});
