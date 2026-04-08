import { readFileSync } from 'node:fs';
import { verifyReceipt } from './verifyReceipt.js';
import { verifyChain } from './verifyChain.js';
import { httpResolver, jwksResolver, fileResolver } from './resolvers.js';
import type { PublicKeyResolver } from './types.js';

const VERSION = '1.0.0-beta.1';

function usage() {
  console.log(`clg-verify v${VERSION}

Usage:
  clg-verify receipt <file>           Verify a single receipt
  clg-verify chain <file>             Verify a chain (JSON array of receipts)

Options:
  --public-key <pem-file>             Use static key from PEM file
  --jwks <url>                        Use JWKS resolver
  --offline                           Require --public-key or --jwks (no HTTP)
  --pretty                            Human-readable output
  --help                              Show this help
  --version                           Show version

Files:
  Use "-" to read from stdin.

Exit codes:
  0  Valid
  1  Invalid
  2  Error (network, parse, file)
`);
}

function readInput(file: string): string {
  if (file === '-') {
    return readFileSync(0, 'utf-8');
  }
  return readFileSync(file, 'utf-8');
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h') || args.length === 0) {
    usage();
    process.exit(0);
  }

  if (args.includes('--version') || args.includes('-v')) {
    console.log(VERSION);
    process.exit(0);
  }

  let publicKeyPath: string | null = null;
  let jwksUrl: string | null = null;
  let offline = false;
  let pretty = false;
  const positional: string[] = [];

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--public-key':
        publicKeyPath = args[++i];
        break;
      case '--jwks':
        jwksUrl = args[++i];
        break;
      case '--offline':
        offline = true;
        break;
      case '--pretty':
        pretty = true;
        break;
      default:
        positional.push(args[i]);
    }
  }

  const command = positional[0];
  const file = positional[1];

  if (!command || !file) {
    console.error('Error: specify command and file. Use --help for usage.');
    process.exit(2);
  }

  // Build resolver
  let resolver: PublicKeyResolver | string;
  if (publicKeyPath) {
    resolver = fileResolver(publicKeyPath);
  } else if (jwksUrl) {
    resolver = jwksResolver(jwksUrl);
  } else if (offline) {
    console.error('Error: --offline requires --public-key or --jwks');
    process.exit(2);
  } else {
    resolver = httpResolver();
  }

  try {
    const raw = readInput(file);
    const data = JSON.parse(raw);

    if (command === 'receipt') {
      const result = await verifyReceipt(data, resolver);
      console.log(pretty ? JSON.stringify(result, null, 2) : JSON.stringify(result));
      process.exit(result.valid ? 0 : 1);
    } else if (command === 'chain') {
      if (!Array.isArray(data)) {
        console.error('Error: chain file must contain a JSON array of receipts');
        process.exit(2);
      }
      const result = await verifyChain(data, resolver);
      console.log(pretty ? JSON.stringify(result, null, 2) : JSON.stringify(result));
      process.exit(result.valid ? 0 : 1);
    } else {
      console.error(`Unknown command: ${command}. Use "receipt" or "chain".`);
      process.exit(2);
    }
  } catch (e) {
    console.error(`Error: ${(e as Error).message}`);
    process.exit(2);
  }
}

main();
