// @typedstandards/host-core: the library (typedstandards#125). Pure and I/O-free over
// in-memory file maps; the `typedstandards-host` bin's Node entry, node/main.ts,
// does the reading and writing. Host Core never holds a key.

export { buildHost, type HostBuild, type RegistryDocument } from './build.ts';
export { checkServed, type CheckReport } from './check.ts';
export { verifyServed, type VerifyOptions, type VerifyReport, type VerifyTotals } from './verify.ts';
export {
  displayOf,
  parsePolicy,
  type Display,
  type DisplayPolicy,
  type DisplayRecord,
  type DisplayRule,
  type ExtensionValue,
} from './display.ts';
export { linksFor, type BadgeTheme, type RecordLinks } from './links.ts';
export { parseManifest, type HostManifest, type HostManifestRecord } from './manifest.ts';
export {
  BUNDLES_DIR,
  INDEX_PATH,
  REGISTRY_PATH,
  bundlePathOf,
  isHostPath,
  parseIndex,
  type HostIndex,
  type IndexRecord,
} from './served.ts';
export { HostError, serialize, type FileMap, type JsonObject } from './json.ts';
