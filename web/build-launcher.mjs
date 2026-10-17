// Builds only the launcher UI. `npm run build` builds everything.
import { buildLauncher } from "./esbuild.launcher.mjs";

await buildLauncher();
