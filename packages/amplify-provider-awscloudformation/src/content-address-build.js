/**
 * Content-address an AppSync build directory so CloudFormation only touches what changed.
 *
 * Problem: the stock CLI mints one S3DeploymentRootKey (hash of the whole source dir) per
 * push. Every resolver/function/stack-template S3 reference embeds that key, so ANY schema
 * change rotates EVERY S3 location -> every AWS::AppSync::FunctionConfiguration, Resolver,
 * and nested-stack TemplateURL takes a property change -> the operation counts ~everything
 * toward CloudFormation's hard 2,500 resources-per-stack-operation limit
 * (aws-amplify/amplify-category-api#2432).
 *
 * Fix: keep the root key CONSTANT and put a content hash in each file's NAME instead:
 *   resolvers/Query.getX.req.vtl      -> resolvers/Query.getX.req.<h10>.vtl
 *   functions/Fn.zip                  -> functions/Fn.<h10>.zip
 *   schema.graphql                    -> schema.<h10>.graphql
 *   stacks/Model.json (post-rewrite)  -> stacks/Model.<h10>.json
 * Unchanged content keeps an identical S3 URL -> CloudFormation skips the resource.
 * Changed content gets a new URL -> exactly those resources update.
 *
 * Because the project root references the API template at a STABLE URL and CloudFormation
 * does not re-read an unchanged nested TemplateURL, the API nested-stack resource still
 * needs one changing property when (and only when) the build changed: an S3BuildFingerprint
 * parameter (hash over the sorted per-file hashes) is declared here and written into
 * parameters.json by upload-appsync-files.js.
 *
 * Runs in upload-appsync-files.js after the transform (and any --minify) finished, before
 * parameters.json is written and files upload. Idempotent per build: the transform always
 * regenerates the build directory with clean names.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const FINGERPRINT_FILE = 'content-fingerprint.json';
const FINGERPRINT_PARAM = 'S3BuildFingerprint';
const SCHEME_VERSION = 'ca1';

const sha10 = (buf) => crypto.createHash('sha256').update(buf).digest('hex').slice(0, 10);

// Query.getContact.auth.1.req.vtl -> Query.getContact.auth.1.req.<h>.vtl (hash before the
// final extension, so tooling that switches on extension keeps working).
const hashedName = (fileName, hash) => {
  const ext = path.extname(fileName);
  return `${fileName.slice(0, fileName.length - ext.length)}.${hash}${ext}`;
};

const listFiles = (dir) => (fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => fs.statSync(path.join(dir, f)).isFile()) : []);

// Renames are applied as plain string replacement in two forms, covering both Fn::Join
// styles the transformer emits: '' -joined segments carrying the S3-relative path
// ("/resolvers/<name>") and '/'-joined segments carrying the bare quoted file name
// ("stacks", "CustomResources.json"). Safe because generated file names are long and
// unique and only ever appear as Fn::Join segments.
const replaceAll = (text, from, to) => text.split(from).join(to);
const applyRenames = (text, renames) => {
  for (const [from, to] of renames) {
    text = replaceAll(text, from, to); // dir/name form
    const fromBase = from.split('/').pop();
    const toBase = to.split('/').pop();
    text = replaceAll(text, `"${fromBase}"`, `"${toBase}"`); // bare quoted-name form
  }
  return text;
};

function contentAddressBuild(buildDir) {
  // The transform empties and regenerates the build directory on every successful run, so
  // this marker can only be present if the build was NOT regenerated since the last rewrite
  // (e.g. a failed compile left the previous build behind). Re-hashing hashed names would
  // corrupt every S3 reference -- refuse loudly instead.
  if (fs.existsSync(path.join(buildDir, FINGERPRINT_FILE))) {
    throw new Error(`${FINGERPRINT_FILE} already present in ${buildDir} -- the build was not regenerated since the last content-address pass. Re-run the transform (amplify api gql-compile) and push again.`);
  }
  const renames = []; // [dirPrefix/oldName, dirPrefix/newName]
  const fileHashes = [];

  for (const dir of ['resolvers', 'pipelineFunctions', 'functions']) {
    const abs = path.join(buildDir, dir);
    for (const f of listFiles(abs)) {
      const h = sha10(fs.readFileSync(path.join(abs, f)));
      const renamed = hashedName(f, h);
      fs.renameSync(path.join(abs, f), path.join(abs, renamed));
      renames.push([`${dir}/${f}`, `${dir}/${renamed}`]);
      fileHashes.push(`${dir}/${f}:${h}`);
    }
  }
  const schemaPath = path.join(buildDir, 'schema.graphql');
  if (fs.existsSync(schemaPath)) {
    const h = sha10(fs.readFileSync(schemaPath));
    const renamed = hashedName('schema.graphql', h);
    fs.renameSync(schemaPath, path.join(buildDir, renamed));
    renames.push(['schema.graphql', renamed]);
    fileHashes.push(`schema.graphql:${h}`);
  }

  // Rewrite asset references inside the nested stack templates, then hash + rename the
  // (now final) templates themselves.
  const stacksDir = path.join(buildDir, 'stacks');
  const stackRenames = [];
  for (const f of listFiles(stacksDir)) {
    const p = path.join(stacksDir, f);
    const text = applyRenames(fs.readFileSync(p, 'utf8'), renames);
    fs.writeFileSync(p, text);
    const h = sha10(text);
    const renamed = hashedName(f, h);
    fs.renameSync(p, path.join(stacksDir, renamed));
    stackRenames.push([`stacks/${f}`, `stacks/${renamed}`]);
    fileHashes.push(`stacks/${f}:${h}`);
  }

  // Root template: rewrite all references, declare the fingerprint parameter.
  const rootPath = path.join(buildDir, 'cloudformation-template.json');
  const rootText = applyRenames(fs.readFileSync(rootPath, 'utf8'), [...renames, ...stackRenames]);
  const rootTemplate = JSON.parse(rootText);
  rootTemplate.Parameters = rootTemplate.Parameters || {};
  rootTemplate.Parameters[FINGERPRINT_PARAM] = {
    Type: 'String',
    Default: '',
    Description: 'Content fingerprint of the API build; changes iff any build artifact changed (content-addressed deploys).',
  };
  const finalRootText = JSON.stringify(rootTemplate, null, 4);
  fs.writeFileSync(rootPath, finalRootText);
  // The root template itself must feed the fingerprint (Codex review, 2026-08-31): it is
  // uploaded to a STABLE amplify-cfn-templates URL, so a root-template-only change (auth
  // config from cli-inputs, CreateAPIKey, LogConfig, ...) deploys ONLY if the fingerprint
  // parameter changes. The fingerprint value lives in parameters.json, not in the template,
  // so hashing the final template text is not circular.
  fileHashes.push(`cloudformation-template.json:${sha10(finalRootText)}`);

  // Any build entry this pass does not understand would upload under an unhashed name and
  // silently stop deploying on content change -- fail loudly instead of guessing.
  const handled = new Set(['resolvers', 'pipelineFunctions', 'functions', 'stacks']);
  const known = new Set(['cloudformation-template.json', 'parameters.json', FINGERPRINT_FILE, 'tsconfig.resource.json', ...renames.map(([, to]) => to)]);
  for (const entry of fs.readdirSync(buildDir)) {
    const isDir = fs.statSync(path.join(buildDir, entry)).isDirectory();
    if ((isDir && !handled.has(entry)) || (!isDir && !known.has(entry))) {
      throw new Error(`content-address-build: unexpected build entry '${entry}' -- extend the content-addressing pass before deploying it.`);
    }
  }

  fileHashes.sort();
  const fingerprint = `${SCHEME_VERSION}-${sha10(Buffer.from(fileHashes.join('\n')))}`;
  fs.writeFileSync(path.join(buildDir, FINGERPRINT_FILE), JSON.stringify({ scheme: SCHEME_VERSION, fingerprint }, null, 2));
  console.error(`>>> CONTENT-ADDRESSED BUILD APPLIED: ${renames.length + stackRenames.length} assets hashed, fingerprint ${fingerprint} <<<`);
  return fingerprint;
}

// Fingerprint of a previously content-addressed build (e.g. #current-cloud-backend), for
// the push paths that rewrite parameters.json without rebuilding. Missing file (first
// patched push, or pre-patch cloud backend) -> empty string, matching the parameter default.
function readBuildFingerprint(buildDir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(buildDir, FINGERPRINT_FILE), 'utf8')).fingerprint || '';
  } catch {
    return '';
  }
}

module.exports = { contentAddressBuild, readBuildFingerprint, FINGERPRINT_PARAM, SCHEME_VERSION };
