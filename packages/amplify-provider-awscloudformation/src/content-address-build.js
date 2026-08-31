/**
 * Content-addressed AppSync deployments: stage a copy of the build directory in which every
 * artifact carries a content hash in its NAME, so CloudFormation only touches resources whose
 * definitions actually changed.
 *
 * Problem: the stock CLI mints one S3DeploymentRootKey (hash of the source dir) per push.
 * Every resolver/function/stack-template S3 reference embeds that key, so ANY schema change
 * rotates EVERY S3 location -> every AWS::AppSync::FunctionConfiguration, Resolver, and
 * nested-stack TemplateURL takes a property change -> the operation counts ~everything toward
 * CloudFormation's hard 2,500 resources-per-stack-operation limit
 * (aws-amplify/amplify-category-api#2432).
 *
 * Design (scheme ca2):
 *  - `backend/.../build` is NEVER renamed in place. Amplify's own safety machinery diffs that
 *    directory against `#current-cloud-backend` KEYED BY FILE NAME (sanity-check.js
 *    loadDiffableProject; graphql-resource-manager getGQLDiff). Renaming in place makes every
 *    stack diff as delete+new, silently disabling the destructive-migration guards and the
 *    iterative-GSI splitter (adversarial review findings F1/F2, 2026-08-31). Both sides of
 *    every diff must stay in transformer-native naming.
 *  - Instead the build is COPIED to a sibling staging directory (`build-ca`), renamed and
 *    reference-rewritten there, and uploaded from there:
 *      resolvers/Query.getX.req.vtl -> resolvers/Query.getX.req.<h16>.vtl
 *      functions/Fn.zip             -> functions/Fn.<h16>.zip
 *      schema.graphql               -> schema.<h16>.graphql
 *      stacks/Model.json            -> stacks/Model.<h16>.json   (after reference rewriting)
 *    Unchanged content keeps an identical S3 URL -> CloudFormation skips the resource.
 *  - The project root references the API template at a STABLE URL and CloudFormation only
 *    re-reads a nested template when the nested-stack resource has a property change. An
 *    S3BuildFingerprint parameter provides that trigger exactly when the build changed. The
 *    fingerprint covers every staged artifact INCLUDING the final root template (review
 *    finding: a root-template-only change -- auth config, CreateAPIKey, LogConfig -- must
 *    flip it). The parameter is DECLARED in `build/cloudformation-template.json` in place
 *    (a root.Parameters addition trips no sanity rule, and upload-appsync-files filters
 *    parameters.json against that file), while all renaming stays in the staged copy.
 *  - `content-fingerprint.json` is written into `build/` so the post-push copy to
 *    `#current-cloud-backend` records the deployed fingerprint; the branches that rewrite
 *    parameters.json without rebuilding read it from #current-cloud-backend (NEVER the local
 *    build, which may be stale or from a rolled-back push -- review finding F3).
 *  - Iterative GSI deployments (build/states) are NOT yet supported: their intermediate step
 *    templates reference transformer-native file names that do not exist under the
 *    content-addressed prefix. Refuse loudly before deploying anything.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const FINGERPRINT_FILE = 'content-fingerprint.json';
const FINGERPRINT_PARAM = 'S3BuildFingerprint';
const SCHEME_VERSION = 'ca2';
const STAGED_DIR_NAME = 'build-ca';
const ROOT_TEMPLATE = 'cloudformation-template.json';

const sha16 = (buf) => crypto.createHash('sha256').update(buf).digest('hex').slice(0, 16);

// Query.getContact.auth.1.req.vtl -> Query.getContact.auth.1.req.<h>.vtl (hash before the
// final extension, so tooling that switches on extension keeps working).
const hashedName = (fileName, hash) => {
  const ext = path.extname(fileName);
  return `${fileName.slice(0, fileName.length - ext.length)}.${hash}${ext}`;
};

const listFiles = (dir) => (fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => fs.statSync(path.join(dir, f)).isFile()) : []);

// Renames are applied as plain string replacement in two forms, covering both Fn::Join styles
// the transformer emits: ''-joined segments carrying the S3-relative path ("/resolvers/<name>")
// and '/'-joined segments carrying the bare quoted file name ("stacks", "CustomResources.json").
// Safe because generated file names are long and unique and only ever appear as Fn::Join segments.
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

const stagedDirFor = (buildDir) => path.join(path.dirname(buildDir), STAGED_DIR_NAME);
const getStagedRootTemplatePath = (buildDir) => path.join(stagedDirFor(buildDir), ROOT_TEMPLATE);

/**
 * Stage `buildDir` into a content-addressed copy and return { stagedDir, fingerprint }.
 * `buildDir` itself is modified only in two name-preserving ways: the fingerprint parameter
 * is declared in its root template, and content-fingerprint.json is (re)written.
 */
function stageContentAddressedBuild(buildDir) {
  const statesDir = path.join(buildDir, 'states');
  if (fs.existsSync(statesDir) && fs.readdirSync(statesDir).length > 0) {
    throw new Error(
      'content-addressed deploys do not yet support iterative GSI deployments (build/states is non-empty): ' +
        'the iterative steps reference transformer-native file names that are not uploaded under the ' +
        'content-addressed prefix. Split the change so each push touches at most one GSI per table.',
    );
  }

  // Declare the fingerprint parameter in the REAL build root, names untouched: the
  // parameters.json filter in upload-appsync-files reads this file, and #current-cloud-backend
  // must carry the declaration too.
  const buildRootPath = path.join(buildDir, ROOT_TEMPLATE);
  const buildRoot = JSON.parse(fs.readFileSync(buildRootPath, 'utf8'));
  buildRoot.Parameters = buildRoot.Parameters || {};
  buildRoot.Parameters[FINGERPRINT_PARAM] = {
    Type: 'String',
    Default: '',
    Description: 'Content fingerprint of the API build; changes iff any build artifact changed (content-addressed deploys).',
  };
  fs.writeFileSync(buildRootPath, JSON.stringify(buildRoot, null, 4));

  // Fresh staged copy. Never uploaded: parameters.json (local input to the parent stack, not a
  // deploy artifact), states (iterative machinery), the previous fingerprint marker, tsconfig.
  const stagedDir = stagedDirFor(buildDir);
  fs.rmSync(stagedDir, { recursive: true, force: true });
  const skip = new Set(['states', 'parameters.json', FINGERPRINT_FILE, 'tsconfig.resource.json']);
  fs.mkdirSync(stagedDir, { recursive: true });
  for (const entry of fs.readdirSync(buildDir)) {
    if (skip.has(entry)) continue;
    fs.cpSync(path.join(buildDir, entry), path.join(stagedDir, entry), { recursive: true });
  }

  const renames = []; // [dirPrefix/oldName, dirPrefix/newName]
  const fileHashes = [];

  for (const dir of ['resolvers', 'pipelineFunctions', 'functions']) {
    const abs = path.join(stagedDir, dir);
    for (const f of listFiles(abs)) {
      const h = sha16(fs.readFileSync(path.join(abs, f)));
      const renamed = hashedName(f, h);
      fs.renameSync(path.join(abs, f), path.join(abs, renamed));
      renames.push([`${dir}/${f}`, `${dir}/${renamed}`]);
      fileHashes.push(`${dir}/${f}:${h}`);
    }
  }
  const schemaPath = path.join(stagedDir, 'schema.graphql');
  if (fs.existsSync(schemaPath)) {
    const h = sha16(fs.readFileSync(schemaPath));
    const renamed = hashedName('schema.graphql', h);
    fs.renameSync(schemaPath, path.join(stagedDir, renamed));
    renames.push(['schema.graphql', renamed]);
    fileHashes.push(`schema.graphql:${h}`);
  }

  // Rewrite asset references inside the nested stack templates, then hash + rename the
  // (now final) templates themselves.
  const stacksDir = path.join(stagedDir, 'stacks');
  const stackRenames = [];
  for (const f of listFiles(stacksDir)) {
    const p = path.join(stacksDir, f);
    const text = applyRenames(fs.readFileSync(p, 'utf8'), renames);
    fs.writeFileSync(p, text);
    const h = sha16(text);
    const renamed = hashedName(f, h);
    fs.renameSync(p, path.join(stacksDir, renamed));
    stackRenames.push([`stacks/${f}`, `stacks/${renamed}`]);
    fileHashes.push(`stacks/${f}:${h}`);
  }

  // Staged root template: rewrite all references. The root template itself must feed the
  // fingerprint: it is uploaded to a STABLE amplify-cfn-templates URL, so a root-only change
  // deploys ONLY if the fingerprint parameter changes. Not circular -- the fingerprint value
  // lives in parameters.json, never in the template.
  const stagedRootPath = path.join(stagedDir, ROOT_TEMPLATE);
  const finalRootText = applyRenames(fs.readFileSync(stagedRootPath, 'utf8'), [...renames, ...stackRenames]);
  fs.writeFileSync(stagedRootPath, finalRootText);
  fileHashes.push(`${ROOT_TEMPLATE}:${sha16(finalRootText)}`);

  // Any staged entry this pass does not understand would upload under an unhashed name and
  // silently stop deploying on content change -- fail loudly instead of guessing.
  const handledDirs = new Set(['resolvers', 'pipelineFunctions', 'functions', 'stacks']);
  const knownFiles = new Set([ROOT_TEMPLATE, ...renames.map(([, to]) => to)]);
  for (const entry of fs.readdirSync(stagedDir)) {
    const isDir = fs.statSync(path.join(stagedDir, entry)).isDirectory();
    if ((isDir && !handledDirs.has(entry)) || (!isDir && !knownFiles.has(entry))) {
      throw new Error(`content-address-build: unexpected build entry '${entry}' -- extend the content-addressing pass before deploying it.`);
    }
  }

  fileHashes.sort();
  const fingerprint = `${SCHEME_VERSION}-${sha16(Buffer.from(fileHashes.join('\n')))}`;
  fs.writeFileSync(path.join(buildDir, FINGERPRINT_FILE), JSON.stringify({ scheme: SCHEME_VERSION, fingerprint }, null, 2));
  console.error(
    `>>> CONTENT-ADDRESSED BUILD STAGED: ${renames.length + stackRenames.length} assets hashed into ${STAGED_DIR_NAME}, fingerprint ${fingerprint} <<<`,
  );
  return { stagedDir, fingerprint };
}

// Fingerprint of a previously staged build, recorded in that build's directory. Callers that
// rewrite parameters.json without rebuilding must read this from #current-cloud-backend (the
// deployed truth), never from the local build (possibly stale or from a rolled-back push).
// Missing file (first patched push, or pre-patch cloud backend) -> empty string, matching the
// parameter default.
function readBuildFingerprint(buildDir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(buildDir, FINGERPRINT_FILE), 'utf8')).fingerprint || '';
  } catch {
    return '';
  }
}

module.exports = {
  stageContentAddressedBuild,
  readBuildFingerprint,
  getStagedRootTemplatePath,
  FINGERPRINT_PARAM,
  SCHEME_VERSION,
  STAGED_DIR_NAME,
};
