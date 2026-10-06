# 🌱 CompAct Jr. — Gerenciador de Equipes

Sistema web multi-organização para gerenciar campeonatos: cadastro de equipes, jogos, competições (mata-mata e grupos + mata-mata), penalidades, classificação em tempo real e auditoria.

---

## 📋 Índice

- [Visão geral](#-visão-geral)
- [Tecnologias](#-tecnologias)
- [Estrutura de pastas](#-estrutura-de-pastas)
- [Como rodar localmente](#-como-rodar-localmente)
- [Variáveis de ambiente](#-variáveis-de-ambiente)
- [Fluxos principais](#-fluxos-principais)
- [Banco de dados](#-banco-de-dados)
- [Deploy no Fly.io](#-deploy-no-flyio)
- [Segurança](#-segurança)
- [Guia de manutenção](#-guia-de-manutenção)

---

## 🎯 Visão geral

O CompAct Jr. é um sistema **multi-tenant** — várias organizações (ex: Medicina, Fisioterapia) usam a mesma instalação, mas cada uma tem seus próprios dados completamente isolados.

**Conceitos principais:**

| Conceito | Descrição |
| :--- | :--- |
| **Organização** | Um "campeonato" ou cliente isolado. Ex: "Medicina", "Fisioterapia" |
| **Usuário** | Login vinculado a uma organização. Pode ser `admin_geral`, `responsavel` ou `organizador` |
| **Equipe** | Time que participa dos jogos da organização |
| **Jogo** | Prova com posições (1º, 2º, 3º...) e pontuações configuráveis |
| **Competição** | Torneio do tipo Mata-Mata ou Grupos + Mata-Mata |
| **Penalidade** | Desconto de pontos com motivo |
| **Auditoria** | Registro de todas as alterações de placar |

**Papéis de usuário:**

| Papel | Escopo | Permissões |
| :--- | :--- | :--- |
| `admin_geral` | Global | Cria organizações, usuários e vê tudo. **Não** cria equipes/jogos/competições |
| `responsavel` | Uma org | Cria, edita e **exclui** tudo na sua organização + cria usuários |
| `organizador` | Uma org | Cria e edita, mas **não exclui** |

---

## 🛠 Tecnologias

- **Backend:** Node.js 20+ com Express
- **Banco de dados:** SQLite (via `better-sqlite3`)
- **Autenticação:** JWT + bcrypt
- **Frontend:** HTML/CSS/JavaScript puro (sem frameworks)
- **PDF:** jsPDF + autoTable (via CDN)
- **Deploy:** Fly.io (com volume persistente)

---

## 📁 Estrutura de pastas

```
copa-agro/
├── data/                    ← banco SQLite (criado automaticamente, ignorado pelo Git)
├── node_modules/            ← dependências (gerado por npm install)
├── public/                  ← arquivos estáticos servidos pelo Express
│   ├── index.html           ← tela pública (sem login) — acompanhar campeonatos
│   └── admin.html           ← painel administrativo (com login)
├── .dockerignore            ← o que NÃO vai para a imagem Docker
├── .gitignore               ← o que NÃO vai para o Git
├── Dockerfile               ← receita para construir a imagem de produção
├── fly.toml                 ← configuração do deploy no Fly.io
├── package.json             ← dependências e scripts
├── db.js                    ← conexão + schema + migrações
├── server.js                ← API Express (todas as rotas)
└── README.md                ← este arquivo
```

---

## 💻 Como rodar localmente

### 1. Pré-requisitos

- Node.js 20 LTS ou superior ([nodejs.org](https://nodejs.org/))
- Git (opcional, mas recomendado)

### 2. Instalar dependências

```bash
cd "caminho/da/pasta"
npm install
```

### 3. Rodar o servidor

```bash
npm start
```

Ou, em modo desenvolvimento (reinicia sozinho ao salvar):

```bash
npm run dev
```

### 4. Acessar

- **Tela pública:** http://localhost:3000
- **Painel admin:** http://localhost:3000/admin

**Login padrão (apenas na primeira vez):**
- Usuário: `admin`
- Senha: `admin123`

> ⚠️ **Troque a senha** logo após o primeiro login, em **Mais → Trocar minha senha**.

### 5. Parar o servidor

`Ctrl + C` no terminal.

---

## 🔐 Variáveis de ambiente

| Variável | Obrigatória? | Padrão | Descrição |
| :--- | :--- | :--- | :--- |
| `PORT` | Não | `3000` | Porta do servidor HTTP |
| `JWT_SECRET` | **Sim em produção** | `'troque-este-segredo-em-producao'` | Segredo usado para assinar tokens JWT. Em produção, use uma string longa e aleatória |
| `DATA_DIR` | Não | `./data` | Pasta onde fica o banco SQLite |
| `ADMIN_USER` | Não | `admin` | Usuário do primeiro admin (só na primeira execução) |
| `ADMIN_PASS` | Não | `admin123` | Senha do primeiro admin (só na primeira execução) |

**Como definir localmente (PowerShell):**

```powershell
$env:JWT_SECRET="uma-frase-muito-longa-e-aleatoria-1234567890"
$env:ADMIN_USER="admin"
$env:ADMIN_PASS="senha-forte-aqui"
npm start
```

**Como definir no Fly.io:**

```bash
flyctl secrets set JWT_SECRET="..."
flyctl secrets set ADMIN_USER="..."
flyctl secrets set ADMIN_PASS="..."
```

---

## 🔄 Fluxos principais

### Login

1. Usuário informa usuário + senha na tela `/admin`
2. Backend valida com `bcrypt.compareSync` contra o hash do banco
3. Se válido, retorna JWT de 7 dias
4. Frontend guarda o token em `localStorage` e o envia no header `Authorization` de todas as requisições

### Criação de um jogo (formato por posição)

1. Responsável abre **Jogos → + Novo jogo**
2. Define nome, posições (1º, 2º, 3º...) com pontuação
3. Marca as equipes participantes
4. Após o jogo, abre **Resultados** e atribui cada posição a uma equipe
5. Backend salva `resultados_json` e registra na auditoria

### Criação de uma competição Mata-Mata

1. Responsável abre **Mata-Mata → + Novo**
2. Escolhe o tipo "Mata-Mata", define pontos de 1º/2º/3º, marca equipes
3. Sistema sorteia as chaves automaticamente
4. A cada vencedor clicado, o sistema propaga para a próxima fase
5. 3º lugar = perdedores das semifinais

### Criação de uma competição Grupos + Mata-Mata

1. Mesmo passo acima, mas escolhendo tipo "Grupos + Mata-Mata"
2. Define número de grupos, quantos classificam por grupo, pontos por vitória/empate
3. Sistema sorteia equipes nos grupos e gera jogos todos-contra-todos
4. Responsável lança os placares de cada jogo
5. Ao final, clica em **⚔️ Gerar mata-mata**
6. Sistema calcula classificados e monta as chaves

### Publicação de dados (tela pública)

1. Jogos e competições têm flag `secreto` (0 ou 1)
2. Se `secreto = 1`, não aparecem em `/api/publico/orgs/:slug`
3. Responsável pode **revelar** jogos individuais ou todos de uma vez

---

## 🗄 Banco de dados

### Tabelas

**`organizacoes`** — organizações (clientes)
```
id, nome, slug, cor, emoji, imagem, ativo, criado_em
```

**`usuarios`** — contas de acesso
```
id (autoincrement), org_id (NULL para admin_geral), usuario,
senha_hash, nome, papel, ativo, criado_em
```

**`equipes`** — times da organização
```
id, org_id, nome, responsavel, criado_em
```

**`jogos`** — provas por posição
```
id, org_id, nome, secreto, posicoes_json, participantes_json,
resultados_json, editado_por, editado_em, criado_em
```

**`penalidades`** — descontos de pontos
```
id, org_id, equipe_id, motivo, pontos, criado_em
```

**`competicoes`** — torneios
```
id, org_id, nome, tipo ('mata_mata'|'grupos_mata_mata'),
secreto, equipes_json, pontos_1, pontos_2, pontos_3,
config_json, editado_por, editado_em, criado_em
```

**`competicoes_partidas`** — confrontos
```
id, competicao_id, rodada, posicao, equipe_a, equipe_b,
vencedor, is_terceiro, grupo, gols_a, gols_b
```

**`auditoria`** — histórico de alterações
```
id (autoincrement), org_id, usuario_id, usuario_nome,
entidade, entidade_id, entidade_nome, acao,
valor_antigo, valor_novo, criado_em
```

### Migrações

As migrações são aplicadas automaticamente em `db.js` sempre que o servidor sobe. A função `addColuna(tabela, coluna, definicao)` verifica se a coluna já existe e, se não, adiciona via `ALTER TABLE`. **Não há risco de perder dados**.

### UTC vs. local

- O SQLite grava `CURRENT_TIMESTAMP` **em UTC**
- O backend não converte nada
- O frontend converte para o fuso do usuário com `fmtData()`

---

## 🚀 Deploy no Fly.io

### Primeira vez

```bash
# 1. Instalar o flyctl (https://fly.io/docs/hands-on/install-flyctl/)
# 2. Autenticar
flyctl auth login

# 3. Criar o app (só uma vez)
flyctl launch
# Responda:
#   - App name: escolha um nome único (ex: compactjr-seunome)
#   - Region: gru (São Paulo)
#   - Postgres? No
#   - Redis? No
#   - Deploy now? No

# 4. Criar o volume persistente (só uma vez)
flyctl volumes create compactjr_data --size 1

# 5. Configurar segredos (só uma vez)
flyctl secrets set JWT_SECRET="uma-frase-muito-longa-e-aleatoria"
flyctl secrets set ADMIN_USER="admin"
flyctl secrets set ADMIN_PASS="uma-senha-forte"

# 6. Fazer deploy
flyctl deploy
```

### Próximos deploys

Depois que a alteração no código estiver salva:

```bash
flyctl deploy
```

### Comandos úteis

| Comando | Para quê |
| :--- | :--- |
| `flyctl status` | Ver se o app está rodando |
| `flyctl logs` | Ver logs em tempo real (`Ctrl+C` para sair) |
| `flyctl open` | Abrir o site no navegador |
| `flyctl ssh console` | Entrar no container |
| `flyctl apps restart` | Reiniciar a máquina |
| `flyctl secrets list` | Listar variáveis configuradas |

### Backup do banco

```bash
flyctl ssh sftp get /data/compactjr.db ./backup-$(date +%Y%m%d).db
```

---

## 🔒 Segurança

| Item | Status |
| :--- | :--- |
| Senhas com hash bcrypt (custo 10) | ✅ |
| JWT com expiração de 7 dias | ✅ |
| HTTPS automático (Let's Encrypt) | ✅ |
| Prepared statements (anti SQL Injection) | ✅ |
| Escape HTML no frontend (anti XSS) | ✅ |
| Multi-tenant com isolamento por `org_id` | ✅ |
| Rate limiting no login | ❌ **Recomendado adicionar** |
| Log de auditoria completo | 🟡 Apenas placar/vencedor |

### Recomendações de segurança para produção

1. **Troque a senha do admin** logo após o primeiro login
2. **Defina `JWT_SECRET` com valor forte** (mínimo 32 caracteres aleatórios)
3. **Não compartilhe a URL** publicamente — apenas com quem precisa
4. **Faça backup** do banco periodicamente
5. **Considere adicionar rate limiting** no endpoint de login (ex: `express-rate-limit`)

---

## 🧭 Guia de manutenção

### Onde mexer para cada tipo de alteração

| Quero... | Mexer em... |
| :--- | :--- |
| Adicionar um campo em equipes | `db.js` (nova coluna) + `server.js` (rotas) + `public/admin.html` (formulário) |
| Mudar as cores do sistema | `public/admin.html` e `public/index.html` (bloco `:root` no CSS) |
| Adicionar uma nova aba | `public/admin.html` (HTML das tabs + função `renderXxx` + case no `switch`) |
| Mudar o texto do login | `public/admin.html` (buscar por `login-card`) |
| Adicionar uma nova organização (pelo site) | Login como admin → **Mais → Organizações → + Nova** |
| Criar um novo usuário responsável | Login como admin → **Mais → Usuários → + Novo** |
| Trocar a senha do admin | Login → **Mais → Trocar minha senha** |
| Alterar o esquema do banco | `db.js` — usar `addColuna()` para migrações seguras |
| Adicionar uma nova rota na API | `server.js` — seguir o padrão `app.metodo('/api/...', auth, ...)` |
| Mudar a paleta (claro/escuro) | `public/*.html` — variáveis CSS em `:root` e `[data-tema="dark"]` |

### Estrutura padrão de uma rota da API

```javascript
app.metodo('/api/recurso', auth, [middleware], (req, res) => {
  // 1. Validar entrada
  // 2. Checar permissão (exigirOrgPropria, exigirPapel, bloquearAdminGeral)
  // 3. Executar no banco (prepared statements)
  // 4. Registrar auditoria (se aplicável)
  // 5. Retornar JSON
});
```

### Estrutura padrão de uma tela no admin

```javascript
window.renderXxx = function(el) {
  el.innerHTML = `...HTML...`;
  // listeners...
};
```

### Ordem de carregamento de arquivos

1. `server.js` → carrega `db.js` (que já roda migrações)
2. `db.js` → cria/atualiza tabelas
3. Rotas do Express são registradas
4. Fallback SPA serve `admin.html` ou `index.html`

### Debug de problemas comuns

| Sintoma | Causa provável | Solução |
| :--- | :--- | :--- |
| "Cannot PUT /api/..." | Rota não existe | Verificar se está antes do `app.get('*', ...)` |
| "no such column: X" | Migração não rodou | Reiniciar o servidor para aplicar `addColuna()` |
| Login não funciona | `</script>` dentro de string | Escapar como `<\/script>` ou usar `window.print()` |
| Modal fecha ao soltar clique fora | Clique começou dentro e terminou fora | Usar `mousedown` + `mouseup` em vez de `click` |
| Horário errado na auditoria | UTC mostrado como local | Usar `fmtData()` que converte corretamente |
| PDF quebrado | jsPDF não carregou | Verificar as tags `<script src="...jspdf...">` no `<head>` |

---

## 📦 Publicação no Git

```bash
git init
git branch -M main
git remote add origin https://github.com/SEU-USUARIO/SEU-REPO.git
git add .
git commit -m "Primeira versão"
git push -u origin main
```

> **Antes de subir**, confirme que `.gitignore` contém `node_modules` e `data`.

---

## 📞 Suporte

Projeto desenvolvido para a CompAct Jr. Em caso de dúvidas sobre manutenção, consulte este README ou os comentários no código.

---

*Última atualização: outubro de 2026*