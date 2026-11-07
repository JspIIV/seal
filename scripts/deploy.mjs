// Deploy Seal end to end on GenLayer Bradbury. On GenLayer Chain (the EVM side, chain 4221): the official EAS
// SchemaRegistry and EAS (from @ethereum-attestation-service/eas-contracts 1.9.0, unmodified, solc 0.8.29), Seal's schema
// "string claim,string source" (revocable, no resolver), and the SealGate. Then the Seal Intelligent Contract, then the
// one time wiring of the gate to it.
//   PCHG=<pw> node scripts/deploy.mjs
import { Wallet, JsonRpcProvider, ContractFactory, Contract } from 'ethers';
import fs from 'fs'; import os from 'os'; import path from 'path';
import { client, fees, EXPLORER } from './net.mjs';
import { compile, ROOT } from './compile.mjs';

const PW = process.env.PCHG || '';
if (!PW) { console.error('set PCHG'); process.exit(1); }
const KS = path.join(os.homedir(), '.genlayer', 'keystores');
const w = await Wallet.fromEncryptedJson(fs.readFileSync(path.join(KS, 'pchg.json'), 'utf8'), PW);
const evm = w.connect(new JsonRpcProvider('https://rpc.testnet-chain.genlayer.com', 4221));
const OUT = path.join(ROOT, 'deployment.json');
const dep = fs.existsSync(OUT) ? JSON.parse(fs.readFileSync(OUT, 'utf8')) : { network: 'genlayer testnet bradbury phase 2', chain_id: 4221 };
const save = () => fs.writeFileSync(OUT, JSON.stringify(dep, null, 2));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const SCHEMA = 'string claim,string source';

async function deploy(key, name, args = []) {
  if (dep[key]) return dep[key].address;
  const c = compile(name);
  fs.mkdirSync(path.join(ROOT, 'evm', 'abi'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'evm', 'abi', name + '.json'), JSON.stringify(c.abi, null, 2));
  const contract = await new ContractFactory(c.abi, c.bytecode, evm).deploy(...args);
  await contract.waitForDeployment();
  dep[key] = { address: await contract.getAddress(), tx: contract.deploymentTransaction().hash };
  dep.compiler = c.version;
  save();
  console.log('deployed', key, dep[key].address);
  return dep[key].address;
}

console.log('deployer', w.address);
const registry = await deploy('schema_registry', 'SchemaRegistry');
const eas = await deploy('eas', 'EAS', [registry]);
if (!dep.schema) {
  const reg = new Contract(registry, compile('SchemaRegistry').abi, evm);
  const rc = await (await reg.register(SCHEMA, '0x0000000000000000000000000000000000000000', true)).wait();
  const ev = rc.logs.map((l) => { try { return reg.interface.parseLog(l); } catch { return null; } }).find((l) => l && l.name === 'Registered');
  dep.schema = { uid: ev.args.uid, definition: SCHEMA, revocable: true, tx: rc.hash };
  save();
  console.log('schema', dep.schema.uid);
}
const gate = await deploy('gate', 'SealGate', [eas, dep.schema.uid]);
if (!dep.seal) {
  const c = client(w.privateKey);
  const code = fs.readFileSync(path.join(ROOT, 'contracts', 'seal.py'), 'utf8');
  const hash = await c.deployContract({ code, args: [gate], fees: await fees(c) });
  console.log('seal tx', hash);
  for (let i = 0; i < 60; i++) {
    await sleep(10000);
    const tx = await c.getTransaction({ hash });
    if (['ACCEPTED', 'FINALIZED'].includes(tx.statusName)) {
      if (tx.txExecutionResultName !== 'FINISHED_WITH_RETURN') { console.error('deploy failed', tx.txExecutionResultName); process.exit(1); }
      dep.seal = { address: tx.txDataDecoded?.contractAddress || tx.recipient, tx: hash };
      dep.address = dep.seal.address; dep.tx = hash; dep.deployed_at = new Date().toISOString();
      save();
      break;
    }
  }
}
if (!dep.wired) {
  const g = new Contract(gate, compile('SealGate').abi, evm);
  await (await g.setSeal(dep.seal.address)).wait();
  dep.wired = true; save();
}
console.log('SEAL', dep.seal?.address, EXPLORER + '/address/' + dep.seal?.address);
console.log('eas', eas, 'registry', registry, 'gate', gate, 'schema', dep.schema.uid);
process.exit(0);
