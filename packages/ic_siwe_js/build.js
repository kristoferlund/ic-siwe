import esbuild from "esbuild";

esbuild.build({
  entryPoints: ["./src/index.ts"],
  bundle: true,
  outdir: "dist",
  format: "esm",
  splitting: true,
  external: [
    "viem",
    "@dfinity/agent",
    "@dfinity/candid",
    "@dfinity/identity",
    "@dfinity/principal",
  ],
  plugins: [],
});

esbuild.build({
  entryPoints: ["./src/react/index.tsx"],
  bundle: true,
  outdir: "dist/react",
  format: "esm",
  splitting: true,
  external: [
    "react",
    "react-dom",
    "viem",
    "wagmi",
    "@dfinity/agent",
    "@dfinity/candid",
    "@dfinity/identity",
    "@dfinity/principal",
  ],
});
