import esbuild from "esbuild";

esbuild.build({
  entryPoints: ["./src/index.tsx"],
  bundle: true,
  outdir: "dist",
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
    "@tanstack/react-query",
  ],
  plugins: [],
});
