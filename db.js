const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'compactjr.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

/* ============ SCHEMA ============ */
db.exec(`
  CREATE TABLE IF NOT EXISTS organizacoes (
    id TEXT PRIMARY KEY,
    nome TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    cor TEXT DEFAULT '#6366f1',
    emoji TEXT DEFAULT '🏆',
    imagem TEXT DEFAULT '',
    ativo INTEGER DEFAULT 1,
    criado_em TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT,
    usuario TEXT UNIQUE NOT NULL,
    senha_hash TEXT NOT NULL,
    nome TEXT NOT NULL,
    papel TEXT NOT NULL DEFAULT 'organizador',
    ativo INTEGER DEFAULT 1,
    criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizacoes(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS equipes (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    nome TEXT NOT NULL,
    responsavel TEXT DEFAULT '',
    criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizacoes(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS jogos (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    nome TEXT NOT NULL,
    secreto INTEGER DEFAULT 0,
    posicoes_json TEXT DEFAULT '[]',
    participantes_json TEXT DEFAULT '[]',
    resultados_json TEXT DEFAULT '{}',
    editado_por TEXT DEFAULT '',
    editado_em TEXT DEFAULT '',
    criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizacoes(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS penalidades (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    equipe_id TEXT NOT NULL,
    motivo TEXT NOT NULL,
    pontos INTEGER NOT NULL DEFAULT 0,
    criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizacoes(id) ON DELETE CASCADE,
    FOREIGN KEY (equipe_id) REFERENCES equipes(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS competicoes (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    nome TEXT NOT NULL,
    tipo TEXT DEFAULT 'mata_mata',
    secreto INTEGER DEFAULT 0,
    equipes_json TEXT DEFAULT '[]',
    pontos_1 INTEGER DEFAULT 0,
    pontos_2 INTEGER DEFAULT 0,
    pontos_3 INTEGER DEFAULT 0,
    config_json TEXT DEFAULT '{}',
    editado_por TEXT DEFAULT '',
    editado_em TEXT DEFAULT '',
    criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizacoes(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS competicoes_partidas (
    id TEXT PRIMARY KEY,
    competicao_id TEXT NOT NULL,
    rodada INTEGER DEFAULT 1,
    posicao INTEGER DEFAULT 0,
    equipe_a TEXT DEFAULT '',
    equipe_b TEXT DEFAULT '',
    vencedor TEXT DEFAULT '',
    is_terceiro INTEGER DEFAULT 0,
    grupo TEXT DEFAULT '',
    gols_a INTEGER,
    gols_b INTEGER,
    FOREIGN KEY (competicao_id) REFERENCES competicoes(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS auditoria (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL,
    usuario_id INTEGER,
    usuario_nome TEXT DEFAULT '',
    entidade TEXT NOT NULL,
    entidade_id TEXT NOT NULL,
    entidade_nome TEXT DEFAULT '',
    acao TEXT NOT NULL,
    valor_antigo TEXT DEFAULT '',
    valor_novo TEXT DEFAULT '',
    criado_em TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_usuarios_org ON usuarios(org_id);
  CREATE INDEX IF NOT EXISTS idx_equipes_org ON equipes(org_id);
  CREATE INDEX IF NOT EXISTS idx_jogos_org ON jogos(org_id);
  CREATE INDEX IF NOT EXISTS idx_penalidades_org ON penalidades(org_id);
  CREATE INDEX IF NOT EXISTS idx_penalidades_equipe ON penalidades(equipe_id);
  CREATE INDEX IF NOT EXISTS idx_competicoes_org ON competicoes(org_id);
  CREATE INDEX IF NOT EXISTS idx_partidas_comp ON competicoes_partidas(competicao_id);
  CREATE INDEX IF NOT EXISTS idx_auditoria_org ON auditoria(org_id);
  CREATE INDEX IF NOT EXISTS idx_auditoria_criado ON auditoria(criado_em);
`);

/* ============ MIGRAÇÕES DE COLUNAS ============ */
function addColuna(tabela, coluna, definicao) {
  const cols = db.prepare(`PRAGMA table_info(${tabela})`).all().map(c => c.name);
  if (!cols.includes(coluna)) {
    db.exec(`ALTER TABLE ${tabela} ADD COLUMN ${coluna} ${definicao}`);
    console.log(`🔧 Migração: ${tabela}.${coluna} adicionada`);
  }
}

addColuna('organizacoes', 'imagem', "TEXT DEFAULT ''");
addColuna('competicoes', 'config_json', "TEXT DEFAULT '{}'");
addColuna('competicoes_partidas', 'grupo', "TEXT DEFAULT ''");
addColuna('competicoes_partidas', 'gols_a', "INTEGER");
addColuna('competicoes_partidas', 'gols_b', "INTEGER");

/* ============ SEED DO ADMIN GERAL ============ */
const adminExiste = db.prepare("SELECT id FROM usuarios WHERE papel='admin_geral' LIMIT 1").get();
if (!adminExiste) {
  const u = process.env.ADMIN_USER || 'admin';
  const p = process.env.ADMIN_PASS || 'admin123';
  const hash = bcrypt.hashSync(p, 10);
  db.prepare(`INSERT INTO usuarios (org_id, usuario, senha_hash, nome, papel)
              VALUES (NULL, ?, ?, ?, 'admin_geral')`).run(u, hash, 'Administrador Geral');
  console.log(`👤 Admin geral criado: ${u} / ${p}`);
}

module.exports = db;