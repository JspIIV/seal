// Independent check that the EVM contracts on GenLayer Chain run exactly the source in this repository and in the
// official EAS package.
//
//   node scripts/verify_evm.mjs
//
// GenLayer Chain's explorer has no source verification service yet, so this does what one would: it compiles EAS,
// SchemaRegistry and SealGate with solc 0.8.29 (the version EAS pins), reads the deployed code from the chain, and
// compares them byte for byte. Immutable values are set by the constructor, so their slots are taken from the chain
// and printed. It also reads Seal's schema back from the SchemaRegistry.
import { JsonRpcProvider, Contract } from 'ethers';
import fs from 'fs'; import path from 'path';
import { compile, ROOT } from './compile.mjs';

const chain = new JsonRpcProvider('https://rpc.testnet-chain.genlayer.com', 4221);
const dep = JSON.parse(fs.readFileSync(path.join(ROOT, 'deployment.json'), 'utf8'));
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'node_modules', '@ethereum-attestation-service', 'eas-contracts', 'package.json'), 'utf8'));

async function check(label, address, name) {
  const { deployed, refs, version } = compile(name);
  const live = (await chain.getCode(address)).slice(2).toLowerCase();
  const filled = deployed.split('');
  const immutables = [];
  for (const spots of Object.values(refs)) {
    for (const { start, length } of spots) {
      for (let i = start * 2; i < (start + length) * 2; i++) filled[i] = live[i];
      immutables.push('0x' + live.slice(start * 2, (start + length) * 2));
    }
  }
  const same = filled.join('') === live;
  console.log(`${same ? 'MATCH    ' : 'DIFFERENT'} ${label.padEnd(15)} ${address}  ${version.split('+')[0]}${immutables.length ? '  immutables ' + [...new Set(immutables)].map((x) => x.slice(0, 26) + '...').join(', ') : ''}`);
  return same;
}

console.log(`@ethereum-attestation-service/eas-contracts ${pkg.version} | optimizer 200 runs, evm paris | chain 4221`);
let all = await check('SchemaRegistry', dep.schema_registry.address, 'SchemaRegistry');
all = (await check('EAS', dep.eas.address, 'EAS')) && all;
all = (await check('SealGate', dep.gate.address, 'SealGate')) && all;
const reg = new Contract(dep.schema_registry.address, compile('SchemaRegistry').abi, chain);
const s = await reg.getSchema(dep.schema.uid);
console.log(`schema ${dep.schema.uid}: "${s.schema}", revocable ${s.revocable}, resolver ${s.resolver}`);
console.log(all ? 'every contract on chain is the source in this repository and the EAS package' : 'at least one contract differs');
process.exit(all ? 0 : 1);
