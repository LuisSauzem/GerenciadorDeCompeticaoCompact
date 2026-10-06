# ============================================================
# Dockerfile — Imagem de produção do CompAct Jr.
# ------------------------------------------------------------
# Usado pelo Fly.io para construir o container que roda o app.
# Base: Alpine Linux (imagem leve de ~50 MB) com Node 20 LTS.
# ============================================================

# Imagem base oficial do Node.js 20 em Alpine
FROM node:20-alpine

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia apenas os arquivos de dependências primeiro
# (isso permite cache do Docker: se o package.json não mudar,
#  o próximo "npm install" é pulado)
COPY package*.json ./

# Instala somente dependências de produção (sem devDependencies)
# --omit=dev é o flag moderno (substituiu --production)
RUN npm install --omit=dev

# Copia o restante do código do projeto para dentro da imagem
COPY . .

# Cria a pasta /data (onde o volume persistente será montado)
# e ajusta o dono para o usuário "node" (não-root) que a imagem traz
RUN mkdir -p /data && chown -R node:node /data

# Define o ambiente como produção
ENV NODE_ENV=production

# Porta que o container expõe (precisa casar com fly.toml)
EXPOSE 3000

# Comando executado quando o container inicia
CMD ["npm", "start"]