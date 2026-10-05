import { existsSync, readFileSync } from 'node:fs';

const schemaPath = 'schema/pricing.v1.json';
const dataPath = 'data/pricing.json';

if (!existsSync(schemaPath)) {
  console.log('no schema yet — schema/pricing.v1.json is absent');
  process.exit(0);
}

const Ajv = (await import('ajv')).default;

const schema = JSON.parse(readFileSync(schemaPath, 'utf-8'));
const data = JSON.parse(readFileSync(dataPath, 'utf-8'));

const ajv = new Ajv({ allErrors: true, strict: false });
const validate = ajv.compile(schema);

if (validate(data)) {
  console.log('valid');
  process.exit(0);
}

console.error('invalid:');
for (const err of validate.errors ?? []) {
  console.error(`  ${err.instancePath || '(root)'}: ${err.message}`);
}
process.exit(1);
