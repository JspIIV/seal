// Compiles the official EAS contracts (from the @ethereum-attestation-service/eas-contracts package, unmodified) and
// SealGate with solc 0.8.29, the exact version EAS pins. Shared by deploy.mjs and verify_evm.mjs.
import solc from 'solc029';
import fs from 'fs'; import path from 'path'; import url from 'url';

export const ROOT = path.join(path.dirname(url.fileURLToPath(import.meta.url)), '..');
export const EAS_DIR = '@ethereum-attestation-service/eas-contracts/contracts/';
export const SETTINGS = { optimizer: { enabled: true, runs: 200 }, evmVersion: 'paris' };
export const SOURCES = {
  SchemaRegistry: EAS_DIR + 'SchemaRegistry.sol',
  EAS: EAS_DIR + 'EAS.sol',
  SealGate: 'SealGate.sol',
};

function findImport(p) {
  for (const base of [path.join(ROOT, 'node_modules'), path.join(ROOT, 'evm')]) {
    const f = path.join(base, p);
    if (fs.existsSync(f)) return { contents: fs.readFileSync(f, 'utf8') };
  }
  return { error: 'not found: ' + p };
}

export function compile(name) {
  const file = SOURCES[name];
  const out = JSON.parse(solc.compile(JSON.stringify({
    language: 'Solidity', sources: { [file]: { content: findImport(file).contents } },
    settings: { ...SETTINGS, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object', 'evm.deployedBytecode.immutableReferences'] } } },
  }), { import: findImport }));
  const errs = (out.errors || []).filter((e) => e.severity === 'error');
  if (errs.length) throw new Error(errs.map((e) => e.formattedMessage).join('\n'));
  const c = out.contracts[file][name];
  return { abi: c.abi, bytecode: '0x' + c.evm.bytecode.object, deployed: c.evm.deployedBytecode.object.toLowerCase(),
    refs: c.evm.deployedBytecode.immutableReferences || {}, version: solc.version() };
}

if (process.argv[1] && process.argv[1].endsWith('compile.mjs')) {
  for (const n of Object.keys(SOURCES)) {
    const c = compile(n);
    fs.mkdirSync(path.join(ROOT, 'evm', 'abi'), { recursive: true });
    fs.writeFileSync(path.join(ROOT, 'evm', 'abi', n + '.json'), JSON.stringify(c.abi, null, 2));
    console.log(n, (c.bytecode.length - 2) / 2, 'bytes', c.version);
  }
}
