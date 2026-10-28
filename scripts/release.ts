import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface Asset {
  name: string;
  digest: string;
}

export interface Existing {
  draft: boolean;
  assets: Asset[];
}

export type Verdict =
  | { kind: "create" }
  | { kind: "matches" }
  | { kind: "draft" }
  | { kind: "differs"; names: string[] };

export const platforms = [
  {
    name: "darwin-arm64",
    os: "darwin",
    arch: "arm64",
    library: "libredact.dylib",
    extension: "dylib",
  },
  { name: "linux-x64", os: "linux", arch: "amd64", library: "libredact.so", extension: "so" },
  { name: "linux-arm64", os: "linux", arch: "arm64", library: "libredact.so", extension: "so" },
] as const;

export function archiveName(platform: string): string {
  return `redact-${platform}.tar.gz`;
}

export function expectedAssetNames(): string[] {
  return [...platforms.map((platform) => archiveName(platform.name)), "SHA256SUMS"].sort();
}

export function cargoVersion(cwd: string): string {
  const manifest = readFileSync(join(cwd, "Cargo.toml"), "utf8");
  const version = /^\[package\][^[]*?^version\s*=\s*"([^"]+)"/ms.exec(manifest)?.[1];
  if (!version) throw new Error("Cargo.toml has no [package] version");

  return version;
}

export function packageRelease({
  cwd,
  libraries,
  dist,
  version,
}: {
  cwd: string;
  libraries: string;
  dist: string;
  version: string;
}): void {
  mkdirSync(dist, { recursive: true });
  const stage = mkdtempSync(join(tmpdir(), "redact-release-"));
  try {
    for (const platform of platforms) {
      const root = join(stage, platform.name);
      const target = join(root, platform.os, platform.arch);
      mkdirSync(target, { recursive: true });
      copyFileSync(
        join(libraries, `library-${platform.name}`, platform.library),
        join(target, `redact-v${version}.${platform.extension}`),
      );

      copyFileSync(join(cwd, "LICENSE.md"), join(root, "LICENSE.md"));
      copyFileSync(join(cwd, "rules", "LICENSE"), join(root, "LICENSE-gitleaks"));

      const archive = join(dist, archiveName(platform.name));
      execFileSync("tar", [
        "--sort=name",
        "--mtime=@0",
        "--owner=0",
        "--group=0",
        "--numeric-owner",
        "--use-compress-program=gzip -n -9",
        "-cf",
        archive,
        "-C",
        root,
        ".",
      ]);
    }
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }

  const sums = readdirSync(dist)
    .filter((name) => name !== "SHA256SUMS")
    .sort()
    .map((name) => `${sha256(join(dist, name))}  ${name}\n`)
    .join("");

  writeFileSync(join(dist, "SHA256SUMS"), sums);
}

export function distAssets(dist: string): Asset[] {
  const names = readdirSync(dist).sort();
  const expected = expectedAssetNames();
  const missing = expected.filter((name) => !names.includes(name));
  const extra = names.filter((name) => !expected.includes(name));
  if (missing.length || extra.length)
    throw new Error(
      [...missing.map((name) => `missing ${name}`), ...extra.map((name) => `extra ${name}`)].join(
        "\n",
      ),
    );

  return names.map((name) => ({ name, digest: sha256(join(dist, name)) }));
}

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export function changelogSection(markdown: string, version: string): string {
  const section: string[] = [];

  let found = false;
  let fence = "";
  for (const line of markdown.split(/\r?\n/)) {
    const marker = /^ {0,3}(`{3,}|~{3,})/.exec(line)?.[1];
    if (fence) {
      if (found) section.push(line);
      if (marker && marker[0] === fence[0] && marker.length >= fence.length) fence = "";
      continue;
    }

    if (marker) {
      fence = marker;
      if (found) section.push(line);
      continue;
    }

    if (/^ {0,3}#{1,2}(?:[ \t]|$)/.test(line)) {
      if (found) break;
      found = line.trim() === `## ${version}`;
      continue;
    }

    if (found) section.push(line);
  }

  const content = section.join("\n").trim();
  if (!found || !content) throw new Error(`missing or blank CHANGELOG.md section for ${version}`);

  return content;
}

export function repo(cwd: string): string {
  if (process.env.GITHUB_REPOSITORY) return process.env.GITHUB_REPOSITORY;

  const manifest = readFileSync(join(cwd, "Cargo.toml"), "utf8");
  const repository = /^repository\s*=\s*"https:\/\/github\.com\/([^/"]+\/[^/"]+?)(?:\.git)?"/m.exec(
    manifest,
  )?.[1];

  if (!repository) throw new Error("Cargo.toml repository must name a GitHub repository");

  return repository;
}

export function existingRelease(cwd: string, tag: string): Existing | undefined {
  const result = spawnSync(
    "gh",
    ["release", "view", tag, "-R", repo(cwd), "--json", "isDraft,assets"],
    { cwd, encoding: "utf8" },
  );

  if (result.error) throw result.error;
  if (result.status !== 0) {
    if (result.stderr.includes("release not found")) return undefined;
    throw new Error(result.stderr.trim());
  }

  const release: {
    isDraft: boolean;
    assets: { name: string; digest: string | null; state: string }[];
  } = JSON.parse(result.stdout);

  return {
    draft: release.isDraft,
    assets: release.assets.map((asset) => ({
      name: asset.name,
      digest: asset.state === "uploaded" ? (asset.digest ?? "").replace(/^sha256:/, "") : "",
    })),
  };
}

export function judge(built: Asset[], existing: Existing | undefined): Verdict {
  if (!existing) return { kind: "create" };
  if (existing.draft) return { kind: "draft" };

  const builtDigests = new Map(built.map((asset) => [asset.name, asset.digest]));
  const existingDigests = new Map(existing.assets.map((asset) => [asset.name, asset.digest]));
  const names = [...new Set([...builtDigests.keys(), ...existingDigests.keys()])]
    .filter((name) => builtDigests.get(name) !== existingDigests.get(name))
    .sort();

  return names.length ? { kind: "differs", names } : { kind: "matches" };
}

export function assertReleasable(verdict: Verdict, tag: string): void {
  if (verdict.kind === "draft")
    throw new Error(`the ${tag} release is still a draft, publish or delete it and rerun`);

  if (verdict.kind === "differs")
    throw new Error(
      verdict.names.map((name) => `${name} does not match the existing ${tag} release`).join("\n"),
    );
}

export function publishRelease({
  cwd,
  dist,
  version,
}: {
  cwd: string;
  dist: string;
  version: string;
}): "created" | "matched" {
  const tag = `v${version}`;
  const notes = changelogSection(readFileSync(join(cwd, "CHANGELOG.md"), "utf8"), version);
  const built = distAssets(dist);
  const verdict = judge(built, existingRelease(cwd, tag));
  assertReleasable(verdict, tag);

  if (verdict.kind === "matches") return "matched";

  const args = [
    "release",
    "create",
    tag,
    ...built.map((asset) => join(dist, asset.name)),
    "-R",
    repo(cwd),
    "--verify-tag",
    "--notes-file",
    "-",
  ];

  if (/^\d+\.\d+\.\d+-/.test(version)) args.push("--prerelease");

  execFileSync("gh", args, { cwd, input: notes, stdio: ["pipe", "inherit", "pipe"] });
  return "created";
}

if (import.meta.main) {
  const [command, ...args] = process.argv.slice(2);
  const cwd = process.cwd();
  try {
    if (command === "package" && args.length === 2) {
      const [libraries, dist] = args as [string, string];
      packageRelease({ cwd, libraries, dist, version: cargoVersion(cwd) });
      process.stdout.write(`release: packaged ${expectedAssetNames().join(", ")}\n`);
    } else if (command === "publish" && args.length === 1) {
      const version = cargoVersion(cwd);
      const result = publishRelease({ cwd, dist: args[0]!, version });
      process.stdout.write(
        result === "created"
          ? `release: created v${version}\n`
          : `release: the existing v${version} release matches ${args[0]}\n`,
      );
    } else {
      process.stderr.write(
        "usage: bun scripts/release.ts package <libraries> <dist>\n       bun scripts/release.ts publish <dist>\n",
      );

      process.exitCode = 2;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(
      message
        .split(/\r?\n/)
        .map((line) => `release: ${line}\n`)
        .join(""),
    );

    process.exitCode = 1;
  }
}
