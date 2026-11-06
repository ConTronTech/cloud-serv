// Build a tar with the web app's own buildFolderTar() (tests/test_tree_archive.sh).
// Usage: node js_tar.mjs <web/app.js> <out.tar>
import fs from "node:fs";
const src = fs.readFileSync(process.argv[2], "utf8");
const a = src.indexOf("const TE = new TextEncoder();"), b = src.indexOf("async function uploadFolderArchive");
const lib = new Function(src.slice(a, b) + "; return { buildFolderTar };")();
const longDir = "Proj/" + Array.from({ length: 8 }, (_, i) => `level-${i}-with-a-longish-name`).join("/");
const mk = (name, data, mtime = 1700000000000) => new File([data], name, { lastModified: mtime });
const big = new Uint8Array(3 * 1024 * 1024 + 17); for (let i = 0; i < big.length; i++) big[i] = (i * 7) & 255;
const items = [
  { dirOnly: true, path: "Proj" }, { dirOnly: true, path: "Proj/src" }, { dirOnly: true, path: "Proj/empty" },
  { file: mk("main.js", "console.log(1)\n"), path: "Proj/src" },
  { file: mk("zero.bin", ""), path: "Proj" },
  { file: mk("café-日本.txt", "unicode\n"), path: "Proj" },
  { file: mk("far.txt", "far\n"), path: longDir },
  { file: mk("big.bin", big), path: "Proj" },
];
const { blob, files } = lib.buildFolderTar("Proj", items);
fs.writeFileSync(process.argv[3], Buffer.from(await blob.arrayBuffer()));
console.log("js tar:", blob.size, "bytes,", files, "files");
