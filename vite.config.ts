import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    build: {
      rollupOptions: {
        input: {
          main: path.resolve(__dirname, 'index.html'),
          dashboard: path.resolve(__dirname, 'dashboard.html'),
          dashboardEmpresa: path.resolve(__dirname, 'dashboard-empresa.html'),
          criarVaga: path.resolve(__dirname, 'criar-vaga.html'),
          vagaDetalhes: path.resolve(__dirname, 'vaga-detalhes.html'),
          candidatos: path.resolve(__dirname, 'candidatos.html'),
          carteira: path.resolve(__dirname, 'carteira.html'),
          perfil: path.resolve(__dirname, 'perfil.html'),
          chat: path.resolve(__dirname, 'chat.html'),
        },
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
