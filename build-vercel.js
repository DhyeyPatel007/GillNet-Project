const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const frontendDir = path.join(__dirname, "GillNet-AI-main");

console.log("--> Starting Vercel Monorepo Build for GillNet AI...");

// Determine package manager
let pm = "npm";
try {
  execSync("bun --version", { stdio: "ignore" });
  pm = "bun";
} catch {
  pm = "npm";
}

console.log(`--> Using package manager: ${pm}`);

// Install dependencies
console.log(`--> Installing dependencies in ${frontendDir}...`);
execSync(`${pm} install`, { cwd: frontendDir, stdio: "inherit" });

// Build using Nitro Vercel preset
console.log(`--> Building frontend with NITRO_PRESET=vercel...`);
const buildCmd = pm === "bun" ? "bun run build:vercel" : "npm run build:vercel";
execSync(buildCmd, {
  cwd: frontendDir,
  stdio: "inherit",
  env: { ...process.env, NITRO_PRESET: "vercel" },
});

// Copy .vercel/output to root .vercel/output for Vercel Build Output API v3
const srcOutput = path.join(frontendDir, ".vercel", "output");
const destOutput = path.join(__dirname, ".vercel", "output");

if (fs.existsSync(srcOutput)) {
  console.log(`--> Copying build output from ${srcOutput} to ${destOutput}...`);
  fs.mkdirSync(path.dirname(destOutput), { recursive: true });
  fs.cpSync(srcOutput, destOutput, { recursive: true });
  console.log("--> Build output ready at .vercel/output!");
} else {
  console.warn("--> Warning: .vercel/output not found in frontend directory.");
}

console.log("--> Vercel build completed successfully!");
