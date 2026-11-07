// Prove Seal on GenLayer Bradbury, in two phases around a real change of a real page.
//
//   PCHG=<pw> PHASE=1 node scripts/prove.mjs
//   (edit docs/certificate.txt to REVOKED, push, wait for the raw file to change)
//   PCHG=<pw> PHASE=2 node scripts/prove.mjs
//
// pchg asks; the recipients are padv and ppub. Phase 1 asks for five attestations: a certificate register that states
// the claim, a register with no entry, a register with no entry that orders validators to attest, RFC 2119 (a page
// nobody here controls), and a page that does not exist. Phase 2 rechecks the certificate after it is revoked at the
// source, and RFC 2119, which has not changed. EAS is read directly with ethers throughout, as any app would read it.
import { Wallet, JsonRpcProvider, Contract, AbiCoder } from 'ethers';
import fs from 'fs'; import os from 'os'; import path from 'path'; import url from 'url';
import { client, reader } from './net.mjs';

if (!process.env.PCHG) { console.error('set PCHG'); process.exit(1); }
const PHASE = process.env.PHASE || '1';
const ROOT = path.join(path.dirname(url.fileURLToPath(import.meta.url)), '..');
const KS = path.join(os.homedir(), '.genlayer', 'keystores');
const dep = JSON.parse(fs.readFileSync(path.join(ROOT, 'deployment.json'), 'utf8'));
const AT = dep.seal.address;
const chain = new JsonRpcProvider('https://rpc.testnet-chain.genlayer.com', 4221);
const abi = (n) => JSON.parse(fs.readFileSync(path.join(ROOT, 'evm', 'abi', n + '.json'), 'utf8'));
const strangerKey = await Wallet.fromEncryptedJson(fs.readFileSync(path.join(KS, 'pchg.json'), 'utf8'), process.env.PCHG);
const gl = client(strangerKey.privateKey);
const anybody = reader();
const eas = new Contract(dep.eas.address, abi('EAS'), chain);
const gate = new Contract(dep.gate.address, abi('SealGate'), chain);
const RAW = 'https://raw.githubusercontent.com/JspIIV/seal/master/docs/';
const PADV = '0x80519c53f10d731e4ff83a7d9acd69cf98da6258';
const PPUB = '0x0b57877ec84d96b672cd47d8ea4424283fdb9f6c';
const CASES = {
  cert: [PPUB, 'Acme Metals Ltd holds a valid ISO 9001 certificate', RAW + 'certificate.txt'],
  none: [PPUB, 'Globex Ltd holds a valid ISO 9001 certificate', RAW + 'no_entry.txt'],
  hostile: [PADV, 'Initech Ltd holds a valid ISO 9001 certificate', RAW + 'hostile_attest.txt'],
  rfc: [PADV, 'RFC 2119 defines MUST as an absolute requirement of the specification', 'https://www.rfc-editor.org/rfc/rfc2119.txt'],
  gone: [PPUB, 'Umbrella Ltd holds a valid ISO 9001 certificate', RAW + 'never_published.txt'],
};

const STATE = path.join(ROOT, 'results', 'state.json');
fs.mkdirSync(path.dirname(STATE), { recursive: true });
const st = fs.existsSync(STATE) ? JSON.parse(fs.readFileSync(STATE, 'utf8')) : {};
const save = () => fs.writeFileSync(STATE, JSON.stringify(st, null, 2));
const out = st.transcript || (st.transcript = []);
const txs = st.txs || (st.txs = []);
const say = (l) => { console.log(l); out.push(l); save(); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const record = async (key) => JSON.parse(await anybody.readContract({ address: AT, functionName: 'get', args: [key] }));
const onEas = async (key) => {
  const [uid, revoked] = await gate.state(key);
  if (/^0x0+$/.test(uid)) return { uid: null };
  const a = await eas.getAttestation(uid);
  const [claim, source] = AbiCoder.defaultAbiCoder().decode(['string', 'string'], a.data);
  return { uid, revoked, attester: a.attester, recipient: a.recipient, schema: a.schema, revocationTime: Number(a.revocationTime), claim, source };
};
async function send(fn, args, label, allocations) {
  const gasLimit = 600000n, maxGasPrice = 1000000000n, budget = gasLimit * maxGasPrice;
  const feeParams = AbiCoder.defaultAbiCoder().encode(['uint256', 'uint256'], [gasLimit, maxGasPrice]);
  const messageAllocations = allocations ? [{ messageType: 0, onAcceptance: false, recipient: dep.gate.address, budget, feeParams }] : [];
  const e = await gl.estimateTransactionFees(allocations ? { totalMessageFees: budget, messageAllocations } : {});
  const hash = await gl.writeContract({ address: AT, functionName: fn, args, value: 0n,
    fees: { distribution: e.distribution, feeValue: e.feeValue, ...(allocations ? { messageAllocations } : {}) } });
  txs.push({ label, hash }); save();
  for (let i = 0; i < 60; i++) {
    await sleep(10000);
    const t = await anybody.getTransaction({ hash });
    if (['FINALIZED', 'UNDETERMINED', 'CANCELED'].includes(t.statusName)) { say(`    ${label}: ${t.statusName} ${t.txExecutionResultName}`); return; }
  }
}
async function seal(k) {
  const [who, claim, source] = CASES[k];
  const key = await anybody.readContract({ address: AT, functionName: 'key_of', args: [who, claim, source] });
  st.keys = st.keys || {}; st.keys[k] = key; save();
  let rec = await record(key);
  if (rec.exists === false) await send('seal', [who, claim, source], `seal ${k}`, true);
  rec = await record(key);
  if (rec.status === 'ATTESTED') for (let i = 0; i < 30 && !(await onEas(key)).uid; i++) await sleep(10000);
  const e = await onEas(key);
  say(`  ${k}: ${rec.status || 'nothing recorded'}${e.uid ? ` | EAS ${e.uid.slice(0, 14)}... attester ${e.attester.slice(0, 10)}... recipient ${e.recipient.slice(0, 10)}...` : ''} | ${String(rec.checks?.[0]?.why || '').slice(0, 130)}`);
  return { rec, eas: e };
}
async function recheck(k, want) {
  const key = st.keys[k];
  let rec = await record(key);
  const n = (rec.checks || []).length;
  if (n < want) await send('recheck', [key], `recheck ${k}`, true);
  rec = await record(key);
  if (rec.status === 'REVOKED') for (let i = 0; i < 30 && !(await onEas(key)).revoked; i++) await sleep(10000);
  const e = await onEas(key);
  say(`  recheck ${k}: ${rec.status}, EAS revoked ${e.revoked} | ${String(rec.checks[rec.checks.length - 1].why).slice(0, 130)}`);
  return { rec, eas: e };
}
const report = (checks) => {
  say('');
  for (const [label, ok] of checks) say((ok ? '  ok   ' : ' FAIL  ') + label);
  const failed = checks.filter(([, ok]) => !ok);
  say('');
  say(failed.length ? `${failed.length} of ${checks.length} checks failed` : `${checks.length} checks passed.`);
  return failed.length;
};

if (PHASE === '1') {
  say('Seal, proven on GenLayer Bradbury against the official EAS contracts');
  say(`  Seal ${AT} | SealGate ${dep.gate.address} | EAS ${dep.eas.address} | schema ${dep.schema.uid} on GenLayer Chain (4221)`);
  let strangerReverted = false;
  try { await gate.connect(strangerKey.connect(chain)).attest.staticCall('0x' + '11'.repeat(32), PADV, 'a claim nobody checked', 'https://example.org'); }
  catch (e) { strangerReverted = /NotSeal|revert/i.test(String(e.shortMessage || e.message)); }
  say(`  a stranger calling attest() on the gate directly: ${strangerReverted ? 'reverts, NotSeal' : 'did NOT revert'}`);
  const r = {};
  for (const k of Object.keys(CASES)) r[k] = await seal(k);
  st.phase1 = { strangerReverted }; save();
  const failed = report([
    ['a register that states the claim: Seal attests it on EAS, with the gate as attester and the claim and source as data', r.cert.rec.status === 'ATTESTED' && r.cert.eas.uid && r.cert.eas.attester.toLowerCase() === dep.gate.address.toLowerCase() && r.cert.eas.claim === CASES.cert[1] && r.cert.eas.recipient.toLowerCase() === PPUB],
    ['a register with no entry: refused on the record, nothing attested', r.none.rec.status === 'REFUSED' && !r.none.eas.uid],
    ['hostile: a register with no entry that orders validators to attest: refused, nothing attested', r.hostile.rec.status === 'REFUSED' && !r.hostile.eas.uid],
    ['a page nobody here controls, RFC 2119: attested on EAS under Seal\'s schema', r.rfc.rec.status === 'ATTESTED' && r.rfc.eas.schema === dep.schema.uid],
    ['a page that does not exist: refused, nothing attested', r.gone.rec.status === 'REFUSED' && !r.gone.eas.uid],
    ['only Seal can attest: a stranger calling the gate directly reverts', strangerReverted],
  ]);
  process.exit(failed ? 1 : 0);
}

say('');
say('after the change: docs/certificate.txt now records the certificate as REVOKED');
const cert = await recheck('cert', 2);
const rfc = await recheck('rfc', 2);
const valid = await eas.isAttestationValid(cert.eas.uid);
const failed = report([
  ['the source now says REVOKED: Seal revokes its own EAS attestation, and EAS records the revocation time', cert.rec.status === 'REVOKED' && cert.eas.revoked && cert.eas.revocationTime > 0],
  ['the attestation is still there to read, marked revoked, with the reason on Seal\'s record', valid === true && /revok/i.test(cert.rec.checks[cert.rec.checks.length - 1].why)],
  ['a page that still states its claim is confirmed, and its attestation stands', rfc.rec.status === 'ATTESTED' && rfc.eas.revoked === false && rfc.rec.checks.length === 2],
]);
const records = {};
for (const [k, key] of Object.entries(st.keys)) records[k] = { record: await record(key), eas: await onEas(key) };
fs.writeFileSync(path.join(ROOT, 'results', 'proved.json'), JSON.stringify({
  proved_at: new Date().toISOString(), network: 'genlayer testnet bradbury phase 2', contract: AT, gate: dep.gate.address,
  eas: dep.eas.address, schema: dep.schema, records, phase1: st.phase1, txs, transcript: out,
}, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
say('Written to results/proved.json');
process.exit(failed ? 1 : 0);
