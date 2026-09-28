import { defineConfig } from "tsdown";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    device: "src/device.ts",
    verify: "src/verify.ts",
  },
  format: "esm",
  platform: "neutral",
  target: "es2022",
  dts: true,
  sourcemap: false,
  clean: true,
});
