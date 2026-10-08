import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import fs from 'fs';

function copyExtensionAssets() {
  return {
    name: 'copy-extension-assets',
    closeBundle() {
      const outDir = resolve(__dirname, 'dist');
      if (!fs.existsSync(outDir)) {
        fs.mkdirSync(outDir, { recursive: true });
      }

      // Copy manifest.json
      const manifestSrc = resolve(__dirname, 'manifest.json');
      const manifestDest = resolve(outDir, 'manifest.json');
      if (fs.existsSync(manifestSrc)) {
        fs.copyFileSync(manifestSrc, manifestDest);
      }

      // Copy icons directory
      const iconsSrcDir = resolve(__dirname, 'icons');
      const iconsDestDir = resolve(outDir, 'icons');
      if (fs.existsSync(iconsSrcDir)) {
        if (!fs.existsSync(iconsDestDir)) {
          fs.mkdirSync(iconsDestDir, { recursive: true });
        }
        for (const file of fs.readdirSync(iconsSrcDir)) {
          fs.copyFileSync(resolve(iconsSrcDir, file), resolve(iconsDestDir, file));
        }
      }
    }
  };
}

export default defineConfig({
  plugins: [react(), copyExtensionAssets()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/popup.html'),
        options: resolve(__dirname, 'src/options/options.html'),
        background: resolve(__dirname, 'src/background/serviceWorker.ts'),
        contentScript: resolve(__dirname, 'src/content/contentScript.ts')
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'background') {
            return 'background.js';
          }
          if (chunkInfo.name === 'contentScript') {
            return 'contentScript.js';
          }
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]'
      }
    }
  }
});
