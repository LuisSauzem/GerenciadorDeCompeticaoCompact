// ============================================================
// server.js — API Express do CompAct Jr.
// ------------------------------------------------------------
// Este arquivo contém TODA a lógica do backend:
//   - Autenticação (login + JWT)
//   - Middlewares de permissão (por papel e por organização)
//   - CRUD de organizações, usuários, equipes, jogos, penalidades
//   - CRUD de competições (mata-mata e grupos + mata-mata)
//   - Geração automática de chaves e propagação de vencedores
//   - Classificação geral e auditoria
//
// Fluxo de uma requisição típica:
//   fetch → auth (valida JWT) → middleware de permissão → handler → res.json
// ============================================================

const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo-em-producao';

// ------------------------------------------------------------
// Middlewares globais
// ------------------------------------------------------------
// express.json()   → parseia corpo JSON (limite de 1 MB)
// express.static() → serve os arquivos da pasta /public
// ------------------------------------------------------------
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------
// uid()     → gera IDs únicos (hex de 16 caracteres)
// slugify() → converte "Medicina UFSM" em "medicina-ufsm"
// ------------------------------------------------------------
const uid = () => crypto.randomBytes(8).toString('hex');
const slugify = s => String(s).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
  .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);


// ============================================================
// AUTENTICAÇÃO E PERMISSÕES
// ============================================================

/**
 * Middleware `auth`
 * ------------------------------------------------------------
 * Roda em TODAS as rotas protegidas.
 *   1. Lê o header "Authorization: Bearer <token>"
 *   2. Valida o JWT com JWT_SECRET
 *   3. Busca o usuário no banco (pra confirmar que ainda está ativo)
 *   4. Injeta `req.user` com { id, org_id, usuario, nome, papel, ativo }
 */
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ erro: 'Não autenticado' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const u = db.prepare('SELECT id, org_id, usuario, nome, papel, ativo FROM usuarios WHERE id = ?').get(payload.id);
    if (!u || !u.ativo) return res.status(401).json({ erro: 'Usuário inativo' });
    req.user = u;
    next();
  } catch {
    res.status(401).json({ erro: 'Sessão inválida' });
  }
}

/**
 * Middleware `exigirPapel(...papeis)`
 * ------------------------------------------------------------
 * Uso: `app.post('/rota', auth, exigirPapel('responsavel'), handler)`
 * Bloqueia se o usuário logado não tiver NENHUM dos papéis listados.
 */
function exigirPapel(...papeis) {
  return (req, res, next) => {
    if (!papeis.includes(req.user.papel)) {
      return res.status(403).json({ erro: 'Sem permissão' });
    }
    next();
  };
}

/**
 * Helper `exigirOrgPropria(req, orgId)`
 * ------------------------------------------------------------
 * Retorna true se:
 *   - o usuário é admin_geral (vê tudo), OU
 *   - o usuário pertence à organização passada
 * Usado dentro dos handlers para checar se o usuário pode
 * mexer num recurso específico de determinada org.
 */
function exigirOrgPropria(req, orgId) {
  if (req.user.papel === 'admin_geral') return true;
  return req.user.org_id === orgId;
}

/**
 * Middleware `bloquearAdminGeral`
 * ------------------------------------------------------------
 * Algumas rotas (equipes, jogos, competições) NÃO podem ser
 * usadas pelo admin geral — ele só cria orgs e usuários.
 * Este middleware retorna 403 se o usuário logado for admin_geral.
 */
function bloquearAdminGeral(req, res, next) {
  if (req.user.papel === 'admin_geral') {
    return res.status(403).json({ erro: 'Admin geral não pode executar essa ação' });
  }
  next();
}


/**
 * Função `registrarAuditoria({ ... })`
 * ------------------------------------------------------------
 * Insere um registro na tabela `auditoria`.
 * Chamada automaticamente sempre que um placar/vencedor muda.
 *
 * Campos gravados:
 *   - Quem (usuario_id, usuario_nome)
 *   - O quê (entidade, entidade_id, entidade_nome)
 *   - Qual ação (acao)
 *   - Valor antes e depois (JSON serializado)
 */
function registrarAuditoria({ orgId, user, entidade, entidadeId, entidadeNome, acao, valorAntigo, valorNovo }) {
  db.prepare(`INSERT INTO auditoria
    (org_id, usuario_id, usuario_nome, entidade, entidade_id, entidade_nome, acao, valor_antigo, valor_novo)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(orgId, user.id, user.nome, entidade, entidadeId, entidadeNome || '',
         acao, JSON.stringify(valorAntigo ?? null), JSON.stringify(valorNovo ?? null));
}


// ============================================================
// ROTAS DE AUTENTICAÇÃO
// ============================================================

/**
 * POST /api/auth/login
 * ------------------------------------------------------------
 * Body: { usuario, senha }
 * Retorna: { token (JWT 7d), usuario: { id, usuario, nome, papel, orgId, orgNome, orgSlug } }
 *
 * O token é gravado no localStorage do frontend e enviado
 * em todas as requisições seguintes via header Authorization.
 */
app.post('/api/auth/login', (req, res) => {
  const { usuario, senha } = req.body || {};
  if (!usuario || !senha) return res.status(400).json({ erro: 'Informe usuário e senha' });
  const u = db.prepare(`SELECT u.*, o.nome AS org_nome, o.slug AS org_slug
                        FROM usuarios u LEFT JOIN organizacoes o ON o.id = u.org_id
                        WHERE u.usuario = ?`).get(usuario);
  // bcrypt.compareSync compara a senha digitada com o hash gravado
  if (!u || !u.ativo || !bcrypt.compareSync(senha, u.senha_hash)) {
    return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
  }
  const token = jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    token,
    usuario: { id: u.id, usuario: u.usuario, nome: u.nome, papel: u.papel,
               orgId: u.org_id, orgNome: u.org_nome, orgSlug: u.org_slug }
  });
});


/**
 * GET /api/me
 * ------------------------------------------------------------
 * Retorna os dados do usuário logado + a organização dele.
 * Usado para verificar se o token ainda é válido.
 */
app.get('/api/me', auth, (req, res) => {
  const org = req.user.org_id
    ? db.prepare('SELECT id, nome, slug, cor, emoji FROM organizacoes WHERE id = ?').get(req.user.org_id)
    : null;
  res.json({ ...req.user, org });
});


/**
 * PUT /api/me/senha
 * ------------------------------------------------------------
 * Body: { senhaAtual, senhaNova }
 * Permite o próprio usuário trocar a senha dele.
 * Valida:
 *   - senhaNova com pelo menos 6 caracteres
 *   - senhaAtual confere com o hash no banco
 */
app.put('/api/me/senha', auth, (req, res) => {
  const { senhaAtual, senhaNova } = req.body || {};
  if (!senhaAtual || !senhaNova) {
    return res.status(400).json({ erro: 'Informe a senha atual e a nova senha' });
  }
  if (senhaNova.length < 6) {
    return res.status(400).json({ erro: 'A nova senha deve ter ao menos 6 caracteres' });
  }

  const u = db.prepare('SELECT senha_hash FROM usuarios WHERE id = ?').get(req.user.id);
  if (!u) return res.status(404).json({ erro: 'Usuário não encontrado' });
  if (!bcrypt.compareSync(senhaAtual, u.senha_hash)) {
    return res.status(400).json({ erro: 'Senha atual incorreta' });
  }

  const hash = bcrypt.hashSync(senhaNova, 10);
  db.prepare('UPDATE usuarios SET senha_hash = ? WHERE id = ?').run(hash, req.user.id);
  res.json({ ok: true });
});


// ============================================================
// ROTAS PÚBLICAS (SEM LOGIN)
// ------------------------------------------------------------
// Usadas pela tela `/` (index.html) — qualquer pessoa acessa.
// Retornam apenas dados de organizações com ativo=1 e jogos/competicoes
// com secreto=0.
// ============================================================

/**
 * GET /api/publico/orgs
 * ------------------------------------------------------------
 * Lista todas as organizações ativas (cards da home).
 * Inclui a contagem de equipes de cada uma.
 */
app.get('/api/publico/orgs', (req, res) => {
  const orgs = db.prepare(`SELECT id, nome, slug, cor, emoji FROM organizacoes
                           WHERE ativo = 1 ORDER BY nome`).all();
  const count = db.prepare(`SELECT COUNT(*) AS n FROM equipes WHERE org_id = ?`);
  const comContagem = orgs.map(o => ({
    ...o,
    equipes: count.get(o.id).n
  }));
  res.json(comContagem);
});


/**
 * GET /api/publico/orgs/:slug
 * ------------------------------------------------------------
 * Retorna TUDO que o público precisa sobre uma organização:
 *   - Dados da org
 *   - Classificação geral (pontos, penalidades, total)
 *   - Jogos públicos (com posições, participantes e resultados)
 *   - Competições públicas (com partidas e grupos calculados)
 *
 * É o endpoint mais pesado do sistema — faz várias queries,
 * calcula a classificação e devolve tudo pronto pro frontend.
 */
app.get('/api/publico/orgs/:slug', (req, res) => {
  // 1. Busca a organização pelo slug
  const org = db.prepare('SELECT id, nome, slug, cor, emoji, imagem FROM organizacoes WHERE slug = ? AND ativo = 1').get(req.params.slug);
  if (!org) return res.status(404).json({ erro: 'Organização não encontrada' });

  // 2. Busca os dados da org (apenas não-secretos)
  const equipes = db.prepare('SELECT id, nome, responsavel FROM equipes WHERE org_id = ? ORDER BY nome').all(org.id);
  const jogos = db.prepare('SELECT * FROM jogos WHERE org_id = ? AND secreto = 0 ORDER BY nome').all(org.id);
  const penalidades = db.prepare('SELECT equipe_id, pontos FROM penalidades WHERE org_id = ?').all(org.id);
  const competicoes = db.prepare('SELECT * FROM competicoes WHERE org_id = ? AND secreto = 0').all(org.id);

  // 3. Inicia o cálculo da classificação (mapa equipeId -> {pontos, penal})
  const mapa = new Map();
  equipes.forEach(e => mapa.set(e.id, { id: e.id, nome: e.nome, pontos: 0, penal: 0 }));

  // 4. Soma pontos dos jogos "por posição"
  jogos.forEach(j => {
    const part = JSON.parse(j.participantes_json || '[]');
    const pos = JSON.parse(j.posicoes_json || '[]');
    const res = JSON.parse(j.resultados_json || '{}');
    part.forEach(eid => {
      const item = mapa.get(eid);
      if (!item) return;
      const pid = res[eid];                        // id da posição atribuída
      const p = pos.find(x => x.id === pid);
      if (p) item.pontos += Number(p.pontos) || 0;
    });
  });

  // 5. Soma pontos das competições (mata-mata e grupos)
  // 5. Soma pontos das competições
competicoes.forEach(c => {
  const partidas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY rodada, posicao').all(c.id);

  // -------- Personalizado --------
  if (c.tipo === 'personalizado') {
    const blocos = db.prepare('SELECT * FROM competicoes_blocos WHERE competicao_id = ?').all(c.id);
    const blocoFinal = blocos.find(b => b.eh_final);
    const blocoTerceiro = blocos.find(b => b.eh_terceiro);

    if (blocoFinal) {
      const finais = partidas
        .filter(p => p.bloco_id === blocoFinal.id && p.vencedor && p.equipe_a && p.equipe_b)
        .sort((a, b) => (b.posicao || 0) - (a.posicao || 0));
      const final = finais[0];
      if (final) {
        const perd = final.vencedor === final.equipe_a ? final.equipe_b : final.equipe_a;
        const v = mapa.get(final.vencedor);
        const p2 = mapa.get(perd);
        if (v) v.pontos += Number(c.pontos_1) || 0;
        if (p2) p2.pontos += Number(c.pontos_2) || 0;
      }
    }
    if (blocoTerceiro) {
      const terceiros = partidas
        .filter(p => p.bloco_id === blocoTerceiro.id && p.vencedor)
        .sort((a, b) => (b.posicao || 0) - (a.posicao || 0));
      const terc = terceiros[0];
      if (terc) {
        const t3 = mapa.get(terc.vencedor);
        if (t3) t3.pontos += Number(c.pontos_3) || 0;
      }
    }
    return;
  }

  // -------- Mata-mata e grupos + mata-mata --------
  const principais = partidas.filter(p => !p.is_terceiro && !p.grupo);
  const terc = partidas.find(p => p.is_terceiro && !p.grupo);
  if (!principais.length) return;
  const maxR = Math.max(...principais.map(p => p.rodada));
  const final = principais.find(p => p.rodada === maxR && p.vencedor && p.equipe_a && p.equipe_b);
  if (final) {
    const perd = final.vencedor === final.equipe_a ? final.equipe_b : final.equipe_a;
    const v = mapa.get(final.vencedor);
    const p2 = mapa.get(perd);
    if (v) v.pontos += Number(c.pontos_1) || 0;
    if (p2) p2.pontos += Number(c.pontos_2) || 0;
  }
  if (terc && terc.vencedor) {
    const t3 = mapa.get(terc.vencedor);
    if (t3) t3.pontos += Number(c.pontos_3) || 0;
  }
});

  // 6. Subtrai as penalidades
  penalidades.forEach(p => {
    const item = mapa.get(p.equipe_id);
    if (item) item.penal += Number(p.pontos) || 0;
  });

  // 7. Ordena: mais pontos primeiro, desempate por nome
  const classificacao = Array.from(mapa.values())
    .map(c => ({ ...c, total: c.pontos - c.penal }))
    .sort((a, b) => b.total - a.total || a.nome.localeCompare(b.nome, 'pt-BR'));

  // 8. Monta a resposta final (jogos e competições em formato "amigável")
  const ptStmt = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY grupo, rodada, posicao, id');
  res.json({
    org,
    equipes: classificacao,
    jogos: jogos.map(j => ({
      id: j.id, nome: j.nome,
      posicoes: JSON.parse(j.posicoes_json || '[]'),
      participantes: JSON.parse(j.participantes_json || '[]'),
      resultados: JSON.parse(j.resultados_json || '{}')
    })),
    competicoes: competicoes.map(c => {
  let cfg = {};
  try { cfg = JSON.parse(c.config_json || '{}'); } catch {}
  const todas = ptStmt.all(c.id).map(p => ({
    id: p.id, rodada: p.rodada, posicao: p.posicao,
    equipeA: p.equipe_a || '', equipeB: p.equipe_b || '',
    vencedor: p.vencedor || '', isTerceiro: !!p.is_terceiro,
    grupo: p.grupo || '', blocoId: p.bloco_id || '',
    golsA: (p.gols_a === null || p.gols_a === undefined) ? null : p.gols_a,
    golsB: (p.gols_b === null || p.gols_b === undefined) ? null : p.gols_b
  }));

  let blocos = null;
  if (c.tipo === 'personalizado') {
    blocos = db.prepare('SELECT * FROM competicoes_blocos WHERE competicao_id = ? ORDER BY ordem').all(c.id)
      .map(b => ({
        id: b.id, nome: b.nome, tipo: b.tipo, ordem: b.ordem,
        ehFinal: !!b.eh_final, ehTerceiro: !!b.eh_terceiro,
        config: (() => { try { return JSON.parse(b.config_json || '{}'); } catch { return {}; } })()
      }));
  }

      // Se for grupos_mata_mata, calcula a classificação de cada grupo
      let gruposOut = null;
      if (c.tipo === 'grupos_mata_mata') {
        const nomesG = [...new Set(todas.filter(p => p.grupo).map(p => p.grupo))].sort();
        gruposOut = nomesG.map(nome => {
          const matches = todas.filter(p => p.grupo === nome);
          const idsSet = new Set();
          matches.forEach(m => { idsSet.add(m.equipeA); idsSet.add(m.equipeB); });
          const ids = Array.from(idsSet).filter(Boolean);
          const mapeadas = matches.map(m => ({
            equipe_a: m.equipeA, equipe_b: m.equipeB, gols_a: m.golsA, gols_b: m.golsB
          }));
          const classif = calcularClassificacaoGrupo(ids, mapeadas, cfg).map(c => ({
            equipeId: c.equipeId, P: c.P, V: c.V, E: c.E, D: c.D,
            GP: c.GP, GC: c.GC, SG: c.SG, PTS: c.PTS
          }));
          return { nome, classificacao: classif, partidas: matches };
        });
      }

      return {
        id: c.id, nome: c.nome, tipo: c.tipo, config: cfg,
        pontos1: c.pontos_1 || 0, pontos2: c.pontos_2 || 0, pontos3: c.pontos_3 || 0,
        partidas: todas,
        grupos: gruposOut,
        blocos: blocos
      };
    })
  });
});


// ============================================================
// ORGANIZAÇÕES (apenas admin_geral)
// ============================================================

/**
 * GET /api/orgs — lista todas as organizações
 * Inclui contagem de usuários e equipes.
 */
app.get('/api/orgs', auth, exigirPapel('admin_geral'), (req, res) => {
  const orgs = db.prepare('SELECT * FROM organizacoes ORDER BY nome').all();
  const countUser = db.prepare('SELECT COUNT(*) AS n FROM usuarios WHERE org_id = ?');
  const countEq = db.prepare('SELECT COUNT(*) AS n FROM equipes WHERE org_id = ?');
  res.json(orgs.map(o => ({
    ...o,
    usuarios: countUser.get(o.id).n,
    equipes: countEq.get(o.id).n
  })));
});

/**
 * POST /api/orgs — cria uma organização
 * Gera slug único a partir do nome (adiciona sufixo se já existir).
 */
app.post('/api/orgs', auth, exigirPapel('admin_geral'), (req, res) => {
  const { nome, cor, emoji } = req.body || {};
  if (!nome || !nome.trim()) return res.status(400).json({ erro: 'Nome é obrigatório' });
  let slug = slugify(nome);
  if (!slug) slug = 'org-' + uid().slice(0, 6);
  // Garante unicidade do slug
  let baseSlug = slug, i = 1;
  while (db.prepare('SELECT id FROM organizacoes WHERE slug = ?').get(slug)) {
    slug = baseSlug + '-' + i++; if (i > 50) return res.status(400).json({ erro: 'Não foi possível gerar slug' });
  }
  const id = uid();
  db.prepare('INSERT INTO organizacoes (id, nome, slug, cor, emoji) VALUES (?, ?, ?, ?, ?)')
    .run(id, nome.trim(), slug, cor || '#0ea5e9', emoji || '🏆');
  res.status(201).json(db.prepare('SELECT * FROM organizacoes WHERE id = ?').get(id));
});

/**
 * PUT /api/orgs/:id — atualiza uma organização
 * Aceita: nome, cor, emoji, ativo
 */
app.put('/api/orgs/:id', auth, exigirPapel('admin_geral'), (req, res) => {
  const { nome, cor, emoji, ativo } = req.body || {};
  const org = db.prepare('SELECT * FROM organizacoes WHERE id = ?').get(req.params.id);
  if (!org) return res.status(404).json({ erro: 'Organização não encontrada' });
  db.prepare('UPDATE organizacoes SET nome=?, cor=?, emoji=?, ativo=? WHERE id=?')
    .run(nome?.trim() || org.nome, cor ?? org.cor, emoji ?? org.emoji,
         ativo === undefined ? org.ativo : (ativo ? 1 : 0), req.params.id);
  res.json(db.prepare('SELECT * FROM organizacoes WHERE id = ?').get(req.params.id));
});

/**
 * DELETE /api/orgs/:id — exclui uma organização
 * CASCADE: apaga tudo dela (usuários, equipes, jogos...).
 */
app.delete('/api/orgs/:id', auth, exigirPapel('admin_geral'), (req, res) => {
  const r = db.prepare('DELETE FROM organizacoes WHERE id = ?').run(req.params.id);
  if (r.changes === 0) return res.status(404).json({ erro: 'Organização não encontrada' });
  res.json({ ok: true });
});


// ============================================================
// USUÁRIOS
// ============================================================

/**
 * GET /api/usuarios
 * ------------------------------------------------------------
 * - admin_geral vê TODOS os usuários (com org_nome)
 * - responsavel vê apenas os da própria org
 */
app.get('/api/usuarios', auth, (req, res) => {
  const where = req.user.papel === 'admin_geral' ? '' : 'WHERE u.org_id = ?';
  const params = req.user.papel === 'admin_geral' ? [] : [req.user.org_id];
  const rows = db.prepare(`SELECT u.id, u.usuario, u.nome, u.papel, u.ativo, u.org_id,
                                  o.nome AS org_nome
                           FROM usuarios u LEFT JOIN organizacoes o ON o.id = u.org_id
                           ${where}
                           ORDER BY u.nome`).all(...params);
  res.json(rows);
});

/**
 * POST /api/usuarios
 * ------------------------------------------------------------
 * - admin_geral cria usuários em QUALQUER org, com papel 'organizador' ou 'responsavel'
 * - responsavel cria apenas 'organizador' na PRÓPRIA org
 */
app.post('/api/usuarios', auth, exigirPapel('responsavel', 'admin_geral'), (req, res) => {
  const { usuario, senha, nome, orgId, papel } = req.body || {};
  if (!usuario || !senha || !nome) return res.status(400).json({ erro: 'Usuário, senha e nome são obrigatórios' });
  if (senha.length < 6) return res.status(400).json({ erro: 'Senha deve ter ao menos 6 caracteres' });

  let orgFinal;
  if (req.user.papel === 'admin_geral') {
    if (!orgId) return res.status(400).json({ erro: 'Informe a organização' });
    orgFinal = orgId;
  } else {
    orgFinal = req.user.org_id;
  }

  // Regra: só admin_geral pode criar responsável
  let papelFinal = 'organizador';
  if (req.user.papel === 'admin_geral' && (papel === 'responsavel' || papel === 'organizador')) {
    papelFinal = papel;
  }

  if (db.prepare('SELECT id FROM usuarios WHERE usuario = ?').get(usuario)) {
    return res.status(400).json({ erro: 'Nome de usuário já existe' });
  }
  const hash = bcrypt.hashSync(senha, 10);
  const r = db.prepare(`INSERT INTO usuarios (org_id, usuario, senha_hash, nome, papel)
                        VALUES (?, ?, ?, ?, ?)`)
    .run(orgFinal, usuario.trim(), hash, nome.trim(), papelFinal);
  res.status(201).json({ id: r.lastInsertRowid, usuario, nome, papel: papelFinal, orgId: orgFinal });
});

/**
 * PUT /api/usuarios/:id — edita nome, senha ou status "ativo"
 * Responsável só pode editar usuários da própria org.
 */
app.put('/api/usuarios/:id', auth, exigirPapel('responsavel', 'admin_geral'), (req, res) => {
  const alvo = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(req.params.id);
  if (!alvo) return res.status(404).json({ erro: 'Usuário não encontrado' });
  if (req.user.papel === 'responsavel' && alvo.org_id !== req.user.org_id) {
    return res.status(403).json({ erro: 'Sem permissão' });
  }
  const { nome, senha, ativo } = req.body || {};
  const novos = {
    nome: nome?.trim() || alvo.nome,
    senha_hash: senha ? bcrypt.hashSync(senha, 10) : alvo.senha_hash,
    ativo: ativo === undefined ? alvo.ativo : (ativo ? 1 : 0)
  };
  db.prepare('UPDATE usuarios SET nome=?, senha_hash=?, ativo=? WHERE id=?')
    .run(novos.nome, novos.senha_hash, novos.ativo, req.params.id);
  res.json({ ok: true });
});

/**
 * DELETE /api/usuarios/:id — exclui usuário
 * Impede:
 *   - excluir a si mesmo
 *   - excluir admin_geral
 *   - responsável excluir usuário de outra org
 */
app.delete('/api/usuarios/:id', auth, exigirPapel('responsavel', 'admin_geral'), (req, res) => {
  const alvo = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(req.params.id);
  if (!alvo) return res.status(404).json({ erro: 'Usuário não encontrado' });
  if (alvo.id === req.user.id) return res.status(400).json({ erro: 'Você não pode excluir a si mesmo' });
  if (alvo.papel === 'admin_geral') return res.status(400).json({ erro: 'Não é possível excluir admin geral' });
  if (req.user.papel === 'responsavel' && alvo.org_id !== req.user.org_id) {
    return res.status(403).json({ erro: 'Sem permissão' });
  }
  db.prepare('DELETE FROM usuarios WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});


// ============================================================
// EQUIPES
// ============================================================
// Regras:
//   - POST/PUT: admin geral NÃO pode (bloquearAdminGeral)
//   - DELETE: só responsável
//   - Todas as rotas respeitam isolamento por org_id
// ============================================================

app.get('/api/equipes', auth, (req, res) => {
  const orgId = req.user.papel === 'admin_geral'
    ? (req.query.orgId || req.user.org_id)
    : req.user.org_id;
  if (!orgId) return res.json([]);
  res.json(db.prepare('SELECT id, nome, responsavel FROM equipes WHERE org_id = ? ORDER BY nome').all(orgId));
});

app.post('/api/equipes', auth, bloquearAdminGeral, (req, res) => {
  const orgId = req.user.papel === 'admin_geral'
    ? (req.body.orgId || req.user.org_id)
    : req.user.org_id;
  if (!orgId) return res.status(400).json({ erro: 'Organização não definida' });
  const { nome, responsavel } = req.body || {};
  if (!nome || !nome.trim()) return res.status(400).json({ erro: 'Nome é obrigatório' });
  const id = uid();
  db.prepare('INSERT INTO equipes (id, org_id, nome, responsavel) VALUES (?, ?, ?, ?)')
    .run(id, orgId, nome.trim(), responsavel || '');
  res.status(201).json({ id, nome: nome.trim(), responsavel: responsavel || '' });
});

app.put('/api/equipes/:id', auth, bloquearAdminGeral, (req, res) => {
  const eq = db.prepare('SELECT * FROM equipes WHERE id = ?').get(req.params.id);
  if (!eq) return res.status(404).json({ erro: 'Equipe não encontrada' });
  if (!exigirOrgPropria(req, eq.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  const { nome, responsavel } = req.body || {};
  if (!nome || !nome.trim()) return res.status(400).json({ erro: 'Nome é obrigatório' });
  db.prepare('UPDATE equipes SET nome=?, responsavel=? WHERE id=?')
    .run(nome.trim(), responsavel || '', req.params.id);
  res.json({ id: req.params.id, nome, responsavel });
});

app.delete('/api/equipes/:id', auth, bloquearAdminGeral, exigirPapel('responsavel'), (req, res) => {
  const eq = db.prepare('SELECT * FROM equipes WHERE id = ?').get(req.params.id);
  if (!eq) return res.status(404).json({ erro: 'Equipe não encontrada' });
  if (!exigirOrgPropria(req, eq.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  db.prepare('DELETE FROM equipes WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});


// ============================================================
// JOGOS (formato "por posição")
// ============================================================

/**
 * Converte uma linha da tabela `jogos` em um objeto "amigável"
 * (faz o parse dos campos JSON).
 */
function mapJogo(row) {
  return {
    id: row.id, org_id: row.org_id, nome: row.nome, secreto: !!row.secreto,
    posicoes: JSON.parse(row.posicoes_json || '[]'),
    participantes: JSON.parse(row.participantes_json || '[]'),
    resultados: JSON.parse(row.resultados_json || '{}'),
    editado_por: row.editado_por || '', editado_em: row.editado_em || ''
  };
}

app.get('/api/jogos', auth, (req, res) => {
  const orgId = req.user.papel === 'admin_geral'
    ? (req.query.orgId || req.user.org_id)
    : req.user.org_id;
  if (!orgId) return res.json([]);
  const rows = db.prepare('SELECT * FROM jogos WHERE org_id = ? ORDER BY nome').all(orgId);
  res.json(rows.map(mapJogo));
});

app.post('/api/jogos', auth, bloquearAdminGeral, (req, res) => {
  const orgId = req.user.papel === 'admin_geral'
    ? (req.body.orgId || req.user.org_id)
    : req.user.org_id;
  if (!orgId) return res.status(400).json({ erro: 'Organização não definida' });
  const { nome, posicoes, participantes, secreto } = req.body || {};
  if (!nome || !nome.trim()) return res.status(400).json({ erro: 'Nome é obrigatório' });
  const id = uid();
  db.prepare(`INSERT INTO jogos (id, org_id, nome, secreto, posicoes_json, participantes_json)
              VALUES (?, ?, ?, ?, ?, ?)`)
    .run(id, orgId, nome.trim(), secreto ? 1 : 0,
         JSON.stringify(posicoes || []), JSON.stringify(participantes || []));
  res.status(201).json(mapJogo(db.prepare('SELECT * FROM jogos WHERE id = ?').get(id)));
});

app.put('/api/jogos/:id', auth, bloquearAdminGeral, (req, res) => {
  const j = db.prepare('SELECT * FROM jogos WHERE id = ?').get(req.params.id);
  if (!j) return res.status(404).json({ erro: 'Jogo não encontrado' });
  if (!exigirOrgPropria(req, j.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  const { nome, posicoes, participantes, secreto } = req.body || {};
  if (!nome || !nome.trim()) return res.status(400).json({ erro: 'Nome é obrigatório' });

  // Ao editar, limpamos resultados que apontam para posições ou equipes
  // que não existem mais (evita "lixo" no banco).
  const novasPos = posicoes || JSON.parse(j.posicoes_json || '[]');
  const novosPart = participantes || JSON.parse(j.participantes_json || '[]');
  const idsPos = novasPos.map(p => p.id);
  const resuAntigo = JSON.parse(j.resultados_json || '{}');
  const resuFinal = {};
  for (const k of Object.keys(resuAntigo)) {
    if (novosPart.includes(k) && idsPos.includes(resuAntigo[k])) resuFinal[k] = resuAntigo[k];
  }

  db.prepare(`UPDATE jogos SET nome=?, posicoes_json=?, participantes_json=?, resultados_json=?, secreto=? WHERE id=?`)
    .run(nome.trim(), JSON.stringify(novasPos), JSON.stringify(novosPart),
         JSON.stringify(resuFinal), secreto ? 1 : 0, req.params.id);
  res.json(mapJogo(db.prepare('SELECT * FROM jogos WHERE id = ?').get(req.params.id)));
});

/**
 * PUT /api/jogos/:id/resultados
 * ------------------------------------------------------------
 * Grava o placar (posição de cada equipe).
 * Body: { resultados: { equipeId: posicaoId } }
 * Registra a alteração na auditoria (com valores antes/depois).
 */
app.put('/api/jogos/:id/resultados', auth, bloquearAdminGeral, (req, res) => {
  const j = db.prepare('SELECT * FROM jogos WHERE id = ?').get(req.params.id);
  if (!j) return res.status(404).json({ erro: 'Jogo não encontrado' });
  if (!exigirOrgPropria(req, j.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  const { resultados } = req.body || {};
  if (!resultados || typeof resultados !== 'object') return res.status(400).json({ erro: 'Resultados inválidos' });

  const antigo = JSON.parse(j.resultados_json || '{}');
  const agora = new Date().toISOString();
  db.prepare('UPDATE jogos SET resultados_json=?, editado_por=?, editado_em=? WHERE id=?')
    .run(JSON.stringify(resultados), req.user.nome, agora, req.params.id);

  registrarAuditoria({
    orgId: j.org_id, user: req.user, entidade: 'jogo',
    entidadeId: j.id, entidadeNome: j.nome, acao: 'alterar_resultado',
    valorAntigo: antigo, valorNovo: resultados
  });

  res.json({ ok: true });
});

// Revelar um jogo secreto individualmente
app.put('/api/jogos/:id/revelar', auth, bloquearAdminGeral, exigirPapel('responsavel'), (req, res) => {
  const j = db.prepare('SELECT * FROM jogos WHERE id = ?').get(req.params.id);
  if (!j) return res.status(404).json({ erro: 'Jogo não encontrado' });
  if (!exigirOrgPropria(req, j.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  db.prepare('UPDATE jogos SET secreto=0 WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// Revelar TODOS os jogos secretos da org de uma vez
app.put('/api/jogos/revelar-todos', auth, bloquearAdminGeral, exigirPapel('responsavel'), (req, res) => {
  const orgId = req.user.papel === 'admin_geral' ? (req.body.orgId || req.user.org_id) : req.user.org_id;
  if (!orgId) return res.status(400).json({ erro: 'Organização não definida' });
  const r = db.prepare('UPDATE jogos SET secreto=0 WHERE org_id=? AND secreto=1').run(orgId);
  res.json({ ok: true, revelados: r.changes });
});

app.delete('/api/jogos/:id', auth, bloquearAdminGeral, exigirPapel('responsavel'), (req, res) => {
  const j = db.prepare('SELECT * FROM jogos WHERE id = ?').get(req.params.id);
  if (!j) return res.status(404).json({ erro: 'Jogo não encontrado' });
  if (!exigirOrgPropria(req, j.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  db.prepare('DELETE FROM jogos WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});


// ============================================================
// PENALIDADES
// ============================================================
// Pontos sempre positivos (o frontend exibe com sinal "−").

app.get('/api/penalidades', auth, (req, res) => {
  const orgId = req.user.papel === 'admin_geral'
    ? (req.query.orgId || req.user.org_id)
    : req.user.org_id;
  if (!orgId) return res.json([]);
  res.json(db.prepare('SELECT id, equipe_id AS equipeId, motivo, pontos FROM penalidades WHERE org_id = ?').all(orgId));
});

app.post('/api/penalidades', auth, bloquearAdminGeral, (req, res) => {
  const orgId = req.user.papel === 'admin_geral'
    ? (req.body.orgId || req.user.org_id)
    : req.user.org_id;
  if (!orgId) return res.status(400).json({ erro: 'Organização não definida' });
  const { equipeId, motivo, pontos } = req.body || {};
  if (!equipeId || !motivo) return res.status(400).json({ erro: 'Equipe e motivo são obrigatórios' });
  // Valida que a equipe existe e é da mesma org
  const eq = db.prepare('SELECT id FROM equipes WHERE id = ? AND org_id = ?').get(equipeId, orgId);
  if (!eq) return res.status(400).json({ erro: 'Equipe inválida' });
  const id = uid();
  const pts = Math.abs(Number(pontos) || 0);
  db.prepare('INSERT INTO penalidades (id, org_id, equipe_id, motivo, pontos) VALUES (?, ?, ?, ?, ?)')
    .run(id, orgId, equipeId, motivo.trim(), pts);
  res.status(201).json({ id, equipeId, motivo: motivo.trim(), pontos: pts });
});

app.put('/api/penalidades/:id', auth, bloquearAdminGeral, (req, res) => {
  const p = db.prepare('SELECT * FROM penalidades WHERE id = ?').get(req.params.id);
  if (!p) return res.status(404).json({ erro: 'Penalidade não encontrada' });
  if (!exigirOrgPropria(req, p.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  const { equipeId, motivo, pontos } = req.body || {};
  if (!equipeId || !motivo) return res.status(400).json({ erro: 'Equipe e motivo são obrigatórios' });
  const pts = Math.abs(Number(pontos) || 0);
  db.prepare('UPDATE penalidades SET equipe_id=?, motivo=?, pontos=? WHERE id=?')
    .run(equipeId, motivo.trim(), pts, req.params.id);
  res.json({ id: req.params.id, equipeId, motivo: motivo.trim(), pontos: pts });
});

app.delete('/api/penalidades/:id', auth, exigirPapel('responsavel', 'admin_geral'), (req, res) => {
  const p = db.prepare('SELECT * FROM penalidades WHERE id = ?').get(req.params.id);
  if (!p) return res.status(404).json({ erro: 'Penalidade não encontrada' });
  if (!exigirOrgPropria(req, p.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  db.prepare('DELETE FROM penalidades WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});


// ============================================================
// COMPETIÇÕES — helpers, geração de chaves e CRUD
// ============================================================

/**
 * Converte uma linha de `competicoes_partidas` em objeto amigável.
 */
function mapPartida(row) {
  return {
    id: row.id,
    rodada: row.rodada || 1,
    posicao: row.posicao || 0,
    equipeA: row.equipe_a || '',
    equipeB: row.equipe_b || '',
    vencedor: row.vencedor || '',
    isTerceiro: !!row.is_terceiro,
    grupo: row.grupo || '',
    blocoId: row.bloco_id || '',
    golsA: (row.gols_a === null || row.gols_a === undefined) ? null : row.gols_a,
    golsB: (row.gols_b === null || row.gols_b === undefined) ? null : row.gols_b
  };
}

/**
 * Converte uma linha de `competicoes` em objeto amigável.
 * Faz o parse do `config_json` (que guarda nº de grupos, pontos etc).
 */
function mapCompeticao(row, partidas) {
  let cfg = {};
  try { cfg = JSON.parse(row.config_json || '{}'); } catch {}
  return {
    id: row.id,
    org_id: row.org_id,
    nome: row.nome,
    tipo: row.tipo || 'mata_mata',
    secreto: !!row.secreto,
    equipes: JSON.parse(row.equipes_json || '[]'),
    pontos1: row.pontos_1 || 0,
    pontos2: row.pontos_2 || 0,
    pontos3: row.pontos_3 || 0,
    config: cfg,
    editado_por: row.editado_por || '',
    editado_em: row.editado_em || '',
    partidas: partidas || []
  };
}

/**
 * `gerarChave(equipesIds)` — geração de chave mata-mata
 * ------------------------------------------------------------
 * 1. Embaralha as equipes (Fisher-Yates)
 * 2. Na primeira rodada, pareia 2 a 2 na ordem
 * 3. Se o número for ímpar, o último ganha um "bye" (vencedor automático)
 * 4. Cria as rodadas seguintes vazias (semi, final...)
 * 5. Adiciona 1 partida extra para a disputa de 3º lugar
 */
function gerarChave(equipesIds) {
  const arr = [...equipesIds];
  // Fisher-Yates shuffle
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  const todas = [];
  let timesRodada = [...arr];
  let rodada = 1;
  while (timesRodada.length > 1) {
    const qtd = Math.ceil(timesRodada.length / 2);
    for (let i = 0; i < qtd; i++) {
      const a = timesRodada[i * 2] || '';
      const b = timesRodada[i * 2 + 1] || '';
      // Se só tem um time, ele já é o vencedor (bye)
      const venc = (a && !b) ? a : (!a && b) ? b : '';
      todas.push({ rodada, posicao: i, equipe_a: a, equipe_b: b, vencedor: venc, is_terceiro: 0 });
    }
    timesRodada = new Array(qtd).fill('');
    rodada++;
  }
  // Disputa de 3º lugar (só se tiver pelo menos 4 equipes)
  if (arr.length >= 4) {
    todas.push({ rodada, posicao: 0, equipe_a: '', equipe_b: '', vencedor: '', is_terceiro: 1 });
  }
  return todas;
}


// ============================================================
// FASE DE GRUPOS — geração, classificação e mata-mata
// ============================================================

// Letras usadas para nomear os grupos: A, B, C, D...
const LETRAS_GRUPO = 'ABCDEFGHIJKLMNOP'.split('');

/**
 * `distribuirGrupos(equipes, numGrupos)` — sorteio dos grupos
 * ------------------------------------------------------------
 * Embaralha as equipes e distribui round-robin (A, B, C, A, B, C...)
 * para que os grupos fiquem com tamanhos equilibrados.
 */
function distribuirGrupos(equipes, numGrupos) {
  const arr = [...equipes];
  // Fisher-Yates
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  const grupos = Array.from({ length: numGrupos }, () => []);
  arr.forEach((eq, i) => { grupos[i % numGrupos].push(eq); });
  return grupos;
}

/**
 * `gerarRoundRobin(equipes)` — todos contra todos
 * ------------------------------------------------------------
 * Implementa o "método do círculo" (rotação):
 *   - Fase 1: fixa 1 time, os outros rotacionam
 *   - Se nº de times for ímpar, adiciona null (bye) para fechar par
 *   - Retorna lista de rodadas, cada rodada com os confrontos dela
 */
function gerarRoundRobin(equipes) {
  const list = [...equipes];
  if (list.length % 2 === 1) list.push(null); // bye
  const n = list.length;
  const half = n / 2;
  const rounds = [];

  for (let r = 0; r < n - 1; r++) {
    const matches = [];
    for (let i = 0; i < half; i++) {
      const a = list[i];
      const b = list[n - 1 - i];
      if (a !== null && b !== null) {
        // Alterna mando de campo a cada rodada
        matches.push(r % 2 === 0 ? { a, b } : { a: b, b: a });
      }
    }
    rounds.push(matches);

    // Rotaciona: mantém o primeiro fixo, gira o resto
    const fixed = list[0];
    const rest = list.slice(1);
    rest.unshift(rest.pop());
    list.length = 0;
    list.push(fixed, ...rest);
  }
  return rounds;
}

/**
 * `calcularClassificacaoGrupo(equipesGrupo, partidas, cfg)` 
 * ------------------------------------------------------------
 * Calcula a tabela de um grupo:
 *   P  = partidas jogadas
 *   V  = vitórias
 *   E  = empates
 *   D  = derrotas
 *   GP = gols pró
 *   GC = gols contra
 *   SG = saldo de gols
 *   PTS = pontos (V × pontosVitoria + E × pontosEmpate)
 * Ordena por: PTS ↓ | SG ↓ | GP ↓ | nome
 */
function calcularClassificacaoGrupo(equipesGrupo, partidasGrupo, cfg) {
  const ptsV = Number(cfg.pontosVitoria) || 3;
  const ptsE = Number(cfg.pontosEmpate) || 1;

  const mapa = new Map();
  equipesGrupo.forEach(eid => mapa.set(eid, {
    equipeId: eid, P: 0, V: 0, E: 0, D: 0, GP: 0, GC: 0, SG: 0, PTS: 0
  }));

  partidasGrupo.forEach(p => {
    // Ignora partidas sem placar lançado ou sem os dois times
    if (!p.equipe_a || !p.equipe_b) return;
    if (p.gols_a === null || p.gols_b === null || p.gols_a === undefined || p.gols_b === undefined) return;
    const a = mapa.get(p.equipe_a);
    const b = mapa.get(p.equipe_b);
    if (!a || !b) return;
    a.P++; b.P++;
    a.GP += p.gols_a; a.GC += p.gols_b;
    b.GP += p.gols_b; b.GC += p.gols_a;
    if (p.gols_a > p.gols_b) { a.V++; a.PTS += ptsV; b.D++; }
    else if (p.gols_a < p.gols_b) { b.V++; b.PTS += ptsV; a.D++; }
    else { a.E++; b.E++; a.PTS += ptsE; b.PTS += ptsE; }
  });

  return Array.from(mapa.values()).map(x => ({
    ...x,
    SG: x.GP - x.GC
  })).sort((x, y) =>
    y.PTS - x.PTS ||
    y.SG - x.SG ||
    y.GP - x.GP ||
    x.equipeId.localeCompare(y.equipeId)
  );
}

/**
 * `gerarPrimeiraRodadaMataMata(classificados, ...)` 
 * ------------------------------------------------------------
 * A partir dos classificados dos grupos, monta os confrontos
 * da primeira rodada do mata-mata.
 *
 * Ordenação tipo Copa: 1ºA, 1ºB, 2ºA, 2ºB...
 *   → 1ºA × último, 2º × penúltimo, etc.
 * Se o número não for potência de 2, completa com nulls (byes).
 */
function gerarPrimeiraRodadaMataMata(classificados, numGrupos, classificadosPorGrupo) {
  // Ordena: 1ºA, 1ºB, 2ºA, 2ºB, ... (primeiro os 1ºs, depois os 2ºs)
  const porPos = [];
  for (let pos = 1; pos <= classificadosPorGrupo; pos++) {
    for (let g = 0; g < numGrupos; g++) {
      const item = classificados.find(c => c.grupoIdx === g && c.posicao === pos);
      if (item) porPos.push(item.equipeId);
    }
  }

  const n = porPos.length;
  // Próxima potência de 2 ≥ n (para saber quantos slots teremos)
  let pot2 = 1;
  while (pot2 < n) pot2 *= 2;

  // Completa com nulls (byes) até chegar em pot2
  const slots = [...porPos];
  while (slots.length < pot2) slots.push(null);

  // Pareamento tipo copa: seed 1 vs seed N, seed 2 vs N-1...
  const confrontos = [];
  for (let i = 0; i < pot2 / 2; i++) {
    confrontos.push({ a: slots[i], b: slots[pot2 - 1 - i] });
  }
  return confrontos;
}


/**
 * `recomputarChave(partidasTodas)` — recalcula toda a árvore
 * ------------------------------------------------------------
 * É o coração do sistema de chaves. Faz:
 *   1. Filtra apenas partidas do mata-mata (grupo === '')
 *   2. Para cada rodada, propaga os vencedores da rodada anterior
 *   3. Valida byes estruturais (times sozinhos avançam sozinhos)
 *   4. Limpa vencedores inválidos (times que não estão mais na partida)
 *   5. Calcula os perdedores das semifinais para a disputa de 3º
 *
 * Chamado sempre que um vencedor é clicado no frontend.
 */
function recomputarChave(partidasTodas) {
  const partidas = partidasTodas.filter(p => !p.grupo);            // só mata-mata
  const principais = partidas.filter(p => !p.is_terceiro);
  const terceiro = partidas.find(p => p.is_terceiro);

  // Agrupa por rodada e ordena por posição
  const porRodada = {};
  principais.forEach(p => {
    if (!porRodada[p.rodada]) porRodada[p.rodada] = [];
    porRodada[p.rodada].push(p);
  });
  const rodadas = Object.keys(porRodada).map(Number).sort((a, b) => a - b);
  rodadas.forEach(r => porRodada[r].sort((a, b) => a.posicao - b.posicao));

  // Loop rodada a rodada, propagando vencedores
  for (let i = 0; i < rodadas.length; i++) {
    const matchups = porRodada[rodadas[i]];
    const prevLen = i > 0 ? porRodada[rodadas[i - 1]].length : 0;

    // 1. Propaga os vencedores da rodada anterior para esta
    if (i > 0) {
      const anteriores = porRodada[rodadas[i - 1]];
      matchups.forEach(m => {
        const pos0 = m.posicao * 2;
        const pos1 = m.posicao * 2 + 1;
        const m0 = anteriores.find(x => x.posicao === pos0);
        const m1 = anteriores.find(x => x.posicao === pos1);

        const time0 = m0 ? (m0.vencedor || '') : '';
        const time1 = m1 ? (m1.vencedor || '') : '';

        const antigoA = m.equipe_a;
        const antigoB = m.equipe_b;
        m.equipe_a = time0;
        m.equipe_b = time1;

        // Se algum dos times mudou, o vencedor antigo não vale mais
        if (antigoA !== m.equipe_a || antigoB !== m.equipe_b) {
          m.vencedor = '';
        }
      });
    }

    // 2. Valida vencedores das partidas desta rodada
    matchups.forEach((m, idx) => {
      const isLast = idx === matchups.length - 1;
      let isBye = false;
      if (i === 0) {
        // Rodada 1: bye se só tem um time definido
        isBye = (!!m.equipe_a) !== (!!m.equipe_b);
      } else {
        // Rodadas 2+: bye só se a anterior teve nº ímpar de partidas
        // e essa é a última partida da rodada
        isBye = (prevLen % 2 === 1) && isLast;
      }

      if (isBye) {
        // Bye estrutural: o único time avança automaticamente
        if (m.equipe_a && !m.equipe_b) m.vencedor = m.equipe_a;
        else if (!m.equipe_a && m.equipe_b) m.vencedor = m.equipe_b;
      } else {
        // Sem os 2 times definidos → não pode ter vencedor
        if (!m.equipe_a || !m.equipe_b) {
          m.vencedor = '';
        }
        // Se o vencedor atual não está na partida, limpa
        if (m.vencedor && m.vencedor !== m.equipe_a && m.vencedor !== m.equipe_b) {
          m.vencedor = '';
        }
      }
      // Sem nenhum time = sem vencedor
      if (!m.equipe_a && !m.equipe_b) m.vencedor = '';
    });
  }

  // 3. Disputa de 3º lugar = perdedores das semifinais
  if (terceiro && rodadas.length >= 2) {
    const semiR = rodadas[rodadas.length - 2];      // penúltima rodada
    const semis = porRodada[semiR];
    let perd1 = '', perd2 = '';
    if (semis[0] && semis[0].vencedor && semis[0].equipe_a && semis[0].equipe_b) {
      perd1 = semis[0].vencedor === semis[0].equipe_a ? semis[0].equipe_b : semis[0].equipe_a;
    }
    if (semis[1] && semis[1].vencedor && semis[1].equipe_a && semis[1].equipe_b) {
      perd2 = semis[1].vencedor === semis[1].equipe_a ? semis[1].equipe_b : semis[1].equipe_a;
    }

    const oldA = terceiro.equipe_a, oldB = terceiro.equipe_b;
    terceiro.equipe_a = perd1;
    terceiro.equipe_b = perd2;

    // Se o vencedor antigo não é mais válido, limpa
    if (oldA !== perd1 || oldB !== perd2) terceiro.vencedor = '';
    if (terceiro.vencedor && terceiro.vencedor !== perd1 && terceiro.vencedor !== perd2) {
      terceiro.vencedor = '';
    }
    // Auto-premiação: se só há um time (semifinal foi bye), ele é o 3º
    if (!terceiro.vencedor) {
      if (perd1 && !perd2) terceiro.vencedor = perd1;
      else if (!perd1 && perd2) terceiro.vencedor = perd2;
    }
  }

  return partidasTodas;
}


// ============================================================
// CRUD DE COMPETIÇÕES
// ============================================================

/**
 * GET /api/competicoes
 * ------------------------------------------------------------
 * Lista todas as competições da org, já com:
 *   - partidas carregadas e mapeadas
 *   - grupos calculados (se for grupos_mata_mata)
 */
app.get('/api/competicoes', auth, (req, res) => {
  const orgId = req.user.papel === 'admin_geral'
    ? (req.query.orgId || req.user.org_id)
    : req.user.org_id;
  if (!orgId) return res.json([]);

  const rows = db.prepare('SELECT * FROM competicoes WHERE org_id = ? ORDER BY criado_em DESC').all(orgId);
  const ptStmt = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY grupo, rodada, posicao, id');

  const resultado = rows.map(r => {
    const partidas = ptStmt.all(r.id).map(mapPartida);
    const comp = mapCompeticao(r, partidas);

    // Se for grupos + mata-mata, calcula a classificação de cada grupo
    if (comp.tipo === 'grupos_mata_mata') {
      const cfg = comp.config || {};
      const nomesG = [...new Set(partidas.filter(p => p.grupo).map(p => p.grupo))].sort();
      comp.grupos = nomesG.map(nome => {
        const matches = partidas.filter(p => p.grupo === nome);
        const idsSet = new Set();
        matches.forEach(m => { idsSet.add(m.equipeA); idsSet.add(m.equipeB); });
        const ids = Array.from(idsSet).filter(Boolean);
        const mapeadas = matches.map(m => ({
          equipe_a: m.equipeA, equipe_b: m.equipeB, gols_a: m.golsA, gols_b: m.golsB
        }));
        const classif = calcularClassificacaoGrupo(ids, mapeadas, cfg);
        return { nome, classificacao: classif, partidas: matches };
      });
    }
    // Blocos (para personalizadas)
    if (comp.tipo === 'personalizado') {
      comp.blocos = db.prepare('SELECT * FROM competicoes_blocos WHERE competicao_id = ? ORDER BY ordem')
        .all(r.id).map(mapBloco);
    }
    return comp;
  });

  res.json(resultado);
});

/**
 * POST /api/competicoes
 * ------------------------------------------------------------
 * Cria uma competição. Comporta-se diferente por tipo:
 *   - mata_mata: gera chave completa na hora
 *   - grupos_mata_mata: distribui em grupos e gera todos-contra-todos
 *     (o mata-mata é gerado depois, quando o usuário clicar no botão)
 */
/* ============================================================
   POST /api/competicoes
   ------------------------------------------------------------
   Cria uma competição. Comporta-se diferente por tipo:
     - mata_mata:        gera chave completa na hora
     - grupos_mata_mata: distribui em grupos e gera todos-contra-todos
                         (o mata-mata é gerado depois, no botão)
     - personalizado:    nasce VAZIA. O admin cria blocos e
                         confrontos pelo editor de blocos.
   ============================================================ */
app.post('/api/competicoes', auth, bloquearAdminGeral, (req, res) => {
  const {
    nome, tipo = 'mata_mata', equipes, pontos1, pontos2, pontos3, secreto,
    numGrupos = 2, classificadosPorGrupo = 2, pontosVitoria = 3, pontosEmpate = 1
  } = req.body || {};

  const orgId = req.user.papel === 'admin_geral'
    ? (req.body.orgId || req.user.org_id)
    : req.user.org_id;
  if (!orgId) return res.status(400).json({ erro: 'Organização não definida' });
  if (!nome || !nome.trim()) return res.status(400).json({ erro: 'Nome é obrigatório' });
  if (!Array.isArray(equipes) || equipes.length < 2) {
    return res.status(400).json({ erro: 'Selecione ao menos 2 equipes' });
  }

  const id = uid();
  const tipoFinal =
    tipo === 'grupos_mata_mata' ? 'grupos_mata_mata' :
    tipo === 'personalizado'    ? 'personalizado' :
                                  'mata_mata';

  // ============================================================
  // RAMO 1 — MATA-MATA SIMPLES
  // ============================================================
  if (tipoFinal === 'mata_mata') {
    const partidas = gerarChave(equipes);
    const tx = db.transaction(() => {
      db.prepare(`INSERT INTO competicoes
        (id, org_id, nome, tipo, secreto, equipes_json, pontos_1, pontos_2, pontos_3, config_json)
        VALUES (?, ?, ?, 'mata_mata', ?, ?, ?, ?, ?, '{}')`)
        .run(id, orgId, nome.trim(), secreto ? 1 : 0, JSON.stringify(equipes),
             Number(pontos1) || 0, Number(pontos2) || 0, Number(pontos3) || 0);

      const ins = db.prepare(`INSERT INTO competicoes_partidas
        (id, competicao_id, rodada, posicao, equipe_a, equipe_b, vencedor, is_terceiro)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
      partidas.forEach(p =>
        ins.run(uid(), id, p.rodada, p.posicao, p.equipe_a, p.equipe_b, p.vencedor, p.is_terceiro)
      );
    });
    tx();

  // ============================================================
  // RAMO 2 — GRUPOS + MATA-MATA
  // ============================================================
  } else if (tipoFinal === 'grupos_mata_mata') {
    const nG  = Math.max(2, Math.min(8, Number(numGrupos) || 2));
    const cPG = Math.max(1, Math.min(4, Number(classificadosPorGrupo) || 2));

    if (equipes.length < nG * 2) {
      return res.status(400).json({
        erro: `Precisa de ao menos ${nG * 2} equipes para ${nG} grupos`
      });
    }

    const grupos = distribuirGrupos(equipes, nG);
    const config = {
      numGrupos: nG,
      classificadosPorGrupo: cPG,
      pontosVitoria: Number(pontosVitoria) || 3,
      pontosEmpate:  Number(pontosEmpate)  || 1,
      gruposGerados: true,
      mataMataGerado: false
    };

    const tx = db.transaction(() => {
      db.prepare(`INSERT INTO competicoes
        (id, org_id, nome, tipo, secreto, equipes_json, pontos_1, pontos_2, pontos_3, config_json)
        VALUES (?, ?, ?, 'grupos_mata_mata', ?, ?, ?, ?, ?, ?)`)
        .run(id, orgId, nome.trim(), secreto ? 1 : 0, JSON.stringify(equipes),
             Number(pontos1) || 0, Number(pontos2) || 0, Number(pontos3) || 0,
             JSON.stringify(config));

      const ins = db.prepare(`INSERT INTO competicoes_partidas
        (id, competicao_id, rodada, posicao, equipe_a, equipe_b, vencedor, is_terceiro, grupo)
        VALUES (?, ?, ?, ?, ?, ?, '', 0, ?)`);

      grupos.forEach((equipesGrupo, gi) => {
        const nomeGrupo = LETRAS_GRUPO[gi];
        const rounds = gerarRoundRobin(equipesGrupo);
        rounds.forEach((matches, ri) => {
          matches.forEach((m, mi) => {
            ins.run(uid(), id, ri + 1, mi, m.a, m.b, nomeGrupo);
          });
        });
      });
    });
    tx();

  // ============================================================
  // RAMO 3 — PERSONALIZADO (livre)
  // ------------------------------------------------------------
  // Nasce VAZIO. Só grava o registro base da competição.
  // Blocos e partidas são criados depois, no editor de blocos
  // (POST /api/competicoes/:id/blocos).
  // ============================================================
  } else if (tipoFinal === 'personalizado') {
    db.prepare(`INSERT INTO competicoes
      (id, org_id, nome, tipo, secreto, equipes_json, pontos_1, pontos_2, pontos_3, config_json)
      VALUES (?, ?, ?, 'personalizado', ?, ?, ?, ?, ?, '{}')`)
      .run(id, orgId, nome.trim(), secreto ? 1 : 0, JSON.stringify(equipes),
           Number(pontos1) || 0, Number(pontos2) || 0, Number(pontos3) || 0);
  }

  // ============================================================
  // Resposta comum aos 3 ramos
  // ============================================================
  const row = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(id);
  const salvas = db.prepare(
    'SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY grupo, rodada, posicao'
  ).all(id).map(mapPartida);

  res.status(201).json(mapCompeticao(row, salvas));
});

/**
 * PUT /api/competicoes/:id — atualiza nome, pontos e flag secreto
 * Não altera o tipo nem as equipes.
 */
app.put('/api/competicoes/:id', auth, bloquearAdminGeral, (req, res) => {
  const { nome, pontos1, pontos2, pontos3, secreto } = req.body || {};
  if (!nome || !nome.trim()) return res.status(400).json({ erro: 'Nome é obrigatório' });

  const atual = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!atual) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, atual.org_id)) return res.status(403).json({ erro: 'Sem permissão' });

  db.prepare(`UPDATE competicoes SET nome=?, pontos_1=?, pontos_2=?, pontos_3=?, secreto=? WHERE id=?`)
    .run(nome.trim(), Number(pontos1) || 0, Number(pontos2) || 0, Number(pontos3) || 0,
         secreto ? 1 : 0, req.params.id);

  const row = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  const salvas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY grupo, rodada, posicao').all(req.params.id).map(mapPartida);
  res.json(mapCompeticao(row, salvas));
});

/**
 * POST /api/competicoes/:id/gerar-chave
 * ------------------------------------------------------------
 * Usado apenas para o tipo mata_mata (botão "Regerar").
 * Apaga todas as partidas atuais e gera nova chave do zero.
 */
app.post('/api/competicoes/:id/gerar-chave', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  const equipes = JSON.parse(c.equipes_json || '[]');
  if (equipes.length < 2) return res.status(400).json({ erro: 'Precisa de ao menos 2 equipes' });
  const partidas = gerarChave(equipes);
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM competicoes_partidas WHERE competicao_id = ?').run(req.params.id);
    const ins = db.prepare(`INSERT INTO competicoes_partidas (id, competicao_id, rodada, posicao, equipe_a, equipe_b, vencedor, is_terceiro)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    partidas.forEach(p => ins.run(uid(), req.params.id, p.rodada, p.posicao, p.equipe_a, p.equipe_b, p.vencedor, p.is_terceiro));
  });
  tx();
  const salvas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY rodada, posicao').all(req.params.id).map(mapPartida);
  res.json(salvas);
});

/* ============================================================
   POST /api/competicoes/:id/montar-chave
   ------------------------------------------------------------
   Cria a chave do mata-mata a partir de confrontos definidos
   MANUALMENTE pelo admin (em vez de sorteados).

   Body: { confrontos: [ { equipeA: 'id-x', equipeB: 'id-y' }, ... ] }

   Apaga APENAS as partidas do mata-mata (grupo = ''); partidas
   de fase de grupos ficam intactas.
   ============================================================ */
/* ============================================================
   POST /api/competicoes/:id/montar-chave
   ------------------------------------------------------------
   Cria a chave do mata-mata a partir de confrontos definidos
   MANUALMENTE pelo admin (em vez de sorteados).

   Body: { confrontos: [ { equipeA: 'id-x', equipeB: 'id-y' }, ... ] }

   Apaga APENAS as partidas do mata-mata (grupo = ''); partidas
   de fase de grupos ficam intactas.
   ============================================================ */
/* ============================================================
   POST /api/competicoes/:id/montar-chave
   ------------------------------------------------------------
   Cria a chave do mata-mata a partir de confrontos definidos
   MANUALMENTE pelo admin (em vez de sorteados).

   Body:
     {
       confrontos: [ { equipeA, equipeB }, ... ],   // rodada 1 (play-in)
       byes:       [ 'id-x', 'id-y', ... ]          // avançam direto
     }

   Quando o número de equipes NÃO é potência de 2, a chave segue
   o padrão de torneios reais:
     - Q = maior potência de 2 ≤ N
     - numConfrontos = N - Q  (play-in, elimina 1 por partida)
     - numByes       = 2*Q - N (avançam direto à próxima fase)

   Ex.: N=12 → Q=8, 4 confrontos preliminares + 4 byes.
        N=6  → Q=4, 2 confrontos preliminares + 2 byes.
        N=8  → Q=8, 4 confrontos, 0 byes (potência de 2).

   Os slots da rodada 1 são INTERCALADOS (match, bye, match, bye...)
   para que, na rodada 2, cada jogo junte um vencedor de play-in
   contra um time que avançou direto.
   ============================================================ */
app.post('/api/competicoes/:id/montar-chave', auth, bloquearAdminGeral, (req, res) => {
  try {
    const comp = db.prepare(
      'SELECT * FROM competicoes WHERE id = ? AND org_id = ?'
    ).get(req.params.id, req.user.org_id);

    if (!comp) return res.status(404).json({ erro: 'Competição não encontrada' });

    const equipesInscritas = JSON.parse(comp.equipes_json || '[]');
    const N = equipesInscritas.length;

    if (N < 2) return res.status(400).json({ erro: 'Precisa de ao menos 2 equipes' });

    // ---------- Calcula estrutura (byes + play-in) ----------
    let Q = 1;
    while (Q * 2 <= N) Q *= 2;
    const numByes      = 2 * Q - N;
    const numConfrontos = N - Q;

    const { confrontos = [], byes = [] } = req.body || {};

    // ---------- Valida quantidade ----------
    if (confrontos.length !== numConfrontos) {
      return res.status(400).json({
        erro: `São esperados ${numConfrontos} confronto(s) preliminar(es)` +
              (numByes ? ` e ${numByes} equipe(s) com bye` : '')
      });
    }
    if (byes.length !== numByes) {
      return res.status(400).json({
        erro: `São esperadas ${numByes} equipe(s) com bye`
      });
    }

    // ---------- Valida cada confronto ----------
    const usados = new Set();
    for (const cf of confrontos) {
      if (!cf.equipeA || !cf.equipeB)
        return res.status(400).json({ erro: 'Preencha todos os confrontos' });
      if (cf.equipeA === cf.equipeB)
        return res.status(400).json({ erro: 'Uma equipe não pode enfrentar a si mesma' });
      if (!equipesInscritas.includes(cf.equipeA) ||
          !equipesInscritas.includes(cf.equipeB))
        return res.status(400).json({ erro: 'Equipe não inscrita nesta competição' });
      if (usados.has(cf.equipeA) || usados.has(cf.equipeB))
        return res.status(400).json({ erro: 'Equipe repetida em dois confrontos' });
      usados.add(cf.equipeA);
      usados.add(cf.equipeB);
    }

    // ---------- Valida cada bye ----------
    for (const b of byes) {
      if (!equipesInscritas.includes(b))
        return res.status(400).json({ erro: 'Equipe com bye não inscrita' });
      if (usados.has(b))
        return res.status(400).json({ erro: 'Equipe com bye também está num confronto' });
      usados.add(b);
    }

    if (usados.size !== N) {
      return res.status(400).json({ erro: 'Todas as equipes precisam ser alocadas' });
    }

    // ---------- Monta os slots da rodada 1 (intercalados) ----------
    // Formato: match, bye, match, bye, ... (+ byes extras no fim)
    const slotsR1 = [];
    for (let i = 0; i < numConfrontos; i++) {
      slotsR1.push({ tipo: 'match', a: confrontos[i].equipeA, b: confrontos[i].equipeB });
      if (i < numByes) {
        slotsR1.push({ tipo: 'bye', time: byes[i] });
      }
    }
    for (let i = numConfrontos; i < numByes; i++) {
      slotsR1.push({ tipo: 'bye', time: byes[i] });
    }
    // slotsR1.length === Q

    const insert = db.prepare(`
      INSERT INTO competicoes_partidas
        (id, competicao_id, rodada, posicao, equipe_a, equipe_b,
         vencedor, is_terceiro, grupo)
      VALUES (?, ?, ?, ?, ?, ?, '', ?, '')
    `);

    const tx = db.transaction(() => {
      // Só apaga partidas do mata-mata (grupo vazio)
      db.prepare(
        "DELETE FROM competicoes_partidas WHERE competicao_id = ? AND grupo = ''"
      ).run(comp.id);

      // ---------- Rodada 1: play-in + byes intercalados ----------
      slotsR1.forEach((s, i) => {
        if (s.tipo === 'match') {
          insert.run(uid(), comp.id, 1, i, s.a, s.b, 0);
        } else {
          // bye: só 1 time; o recomputarChave() já promove sozinho
          insert.run(uid(), comp.id, 1, i, s.time, '', 0);
        }
      });

      // ---------- Rodadas seguintes (vazias), sempre /2 ----------
      // Q é potência de 2, então essa divisão é sempre exata.
      let slots = Q;
      let rodada = 2;
      while (slots > 1) {
        const slotsProx = slots / 2;
        for (let i = 0; i < slotsProx; i++) {
          insert.run(uid(), comp.id, rodada, i, '', '', 0);
        }
        slots = slotsProx;
        rodada++;
      }

      // ---------- Disputa de 3º lugar (só se houver semi) ----------
      if (Q >= 4) {
        insert.run(uid(), comp.id, rodada, 0, '', '', 1);
      }

      // Marca no config_json
      const cfg = JSON.parse(comp.config_json || '{}');
      cfg.mataMataGerado = true;
      cfg.montagemManual = true;
      cfg.byes = numByes;
      db.prepare('UPDATE competicoes SET config_json = ? WHERE id = ?')
        .run(JSON.stringify(cfg), comp.id);
    });

    tx();
    res.json({ ok: true, numByes, numConfrontos });

  } catch (e) {
    console.error('[montar-chave] erro:', e);
    res.status(500).json({ erro: 'Erro interno: ' + e.message });
  }
});

/**
 * PUT /api/competicoes/:id/partidas/:pid/vencedor
 * ------------------------------------------------------------
 * Marca o vencedor de uma partida do mata-mata.
 * Após gravar, chama recomputarChave() para propagar.
 * Registra na auditoria.
 */
app.put('/api/competicoes/:id/partidas/:pid/vencedor', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  const { vencedor } = req.body || {};

  const partidas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY rodada, posicao, id').all(req.params.id);
  const alvo = partidas.find(x => x.id === req.params.pid);
  if (!alvo) return res.status(404).json({ erro: 'Partida não encontrada' });
  // Em competições personalizadas, não propaga automaticamente —
// o admin escolhe manualmente quem entra em cada confronto.
  if (c.tipo === 'personalizado') {
    db.prepare('UPDATE competicoes_partidas SET vencedor=? WHERE id=?')
      .run(String(vencedor || ''), alvo.id);
    const salvas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY bloco_id, posicao, rodada').all(req.params.id).map(mapPartida);
    return res.json(salvas);
  }

  const antigoVenc = alvo.vencedor;
  alvo.vencedor = String(vencedor || '');

  // Prepara dados para recomputar (incluindo grupo para filtrar)
  const mapeadas = partidas.map(x => ({
    id: x.id, rodada: x.rodada, posicao: x.posicao,
    equipe_a: x.equipe_a, equipe_b: x.equipe_b,
    vencedor: x.vencedor, is_terceiro: x.is_terceiro,
    grupo: x.grupo || ''
  }));
  recomputarChave(mapeadas);

  const agora = new Date().toISOString();
  const tx = db.transaction(() => {
    const upd = db.prepare('UPDATE competicoes_partidas SET equipe_a=?, equipe_b=?, vencedor=? WHERE id=?');
    mapeadas.forEach(x => upd.run(x.equipe_a, x.equipe_b, x.vencedor, x.id));
    db.prepare('UPDATE competicoes SET editado_por=?, editado_em=? WHERE id=?').run(req.user.nome, agora, req.params.id);
  });
  tx();

  registrarAuditoria({
    orgId: c.org_id, user: req.user, entidade: 'competicao',
    entidadeId: c.id, entidadeNome: c.nome, acao: 'alterar_vencedor',
    valorAntigo: { partida: alvo.id, vencedor: antigoVenc },
    valorNovo: { partida: alvo.id, vencedor: alvo.vencedor }
  });

  const salvas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY rodada, posicao').all(req.params.id).map(mapPartida);
  res.json(salvas);
});

// Revelar competição (tornar pública)
app.put('/api/competicoes/:id/revelar', auth, bloquearAdminGeral, exigirPapel('responsavel'), (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  db.prepare('UPDATE competicoes SET secreto=0 WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

/**
 * PUT /api/competicoes/:id/partidas/:pid/placar
 * ------------------------------------------------------------
 * Grava o placar (gols) de uma partida de grupo.
 * Só funciona se a partida tiver `grupo` preenchido.
 */
app.put('/api/competicoes/:id/partidas/:pid/placar', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });

  const p = db.prepare('SELECT * FROM competicoes_partidas WHERE id = ? AND competicao_id = ?')
    .get(req.params.pid, c.id);
  if (!p) return res.status(404).json({ erro: 'Partida não encontrada' });
    // Aceita placar em partidas de grupo OU em partidas de bloco tipo 'grupo'
      // Aceita placar em partidas de grupo, repescagem, ou em partidas de bloco
    // dos tipos 'grupo' e 'repescagem'
    // Aceita placar em partidas de grupo OU em partidas de bloco tipo 'grupo'
    let blocoAceitaPlacar = false;
if (p.bloco_id) {
  const bl = db.prepare('SELECT tipo FROM competicoes_blocos WHERE id = ?').get(p.bloco_id);
  blocoAceitaPlacar = bl && (bl.tipo === 'grupo' || bl.tipo === 'repescagem');
}
if (!p.grupo && !blocoAceitaPlacar) {
  return res.status(400).json({ erro: 'Só é possível lançar placar em partidas de grupo ou repescagem' });
}

  const { golsA, golsB } = req.body || {};
  const ga = (golsA === null || golsA === undefined || golsA === '') ? null : Number(golsA);
  const gb = (golsB === null || golsB === undefined || golsB === '') ? null : Number(golsB);

  if ((ga !== null && (isNaN(ga) || ga < 0)) || (gb !== null && (isNaN(gb) || gb < 0))) {
    return res.status(400).json({ erro: 'Placar inválido' });
  }

  db.prepare('UPDATE competicoes_partidas SET gols_a=?, gols_b=?, vencedor=? WHERE id=?')
    .run(ga, gb, '', p.id);
  db.prepare('UPDATE competicoes SET editado_por=?, editado_em=? WHERE id=?')
    .run(req.user.nome, new Date().toISOString(), c.id);

  const salvas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY grupo, rodada, posicao').all(c.id).map(mapPartida);
  res.json(salvas);
});

/**
 * POST /api/competicoes/:id/sortear-grupos
 * ------------------------------------------------------------
 * Refaz o sorteio dos grupos (só funciona se nenhum placar foi lançado).
 */
app.post('/api/competicoes/:id/sortear-grupos', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  if (c.tipo !== 'grupos_mata_mata') return res.status(400).json({ erro: 'Competição não é do tipo grupos + mata-mata' });

  // Bloqueia se já houver placar
  const partidas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ?').all(c.id);
  const temPlacar = partidas.some(p => p.gols_a !== null && p.gols_b !== null);
  if (temPlacar) return res.status(400).json({ erro: 'Já há placares lançados. Não é possível resortear.' });

  const cfg = JSON.parse(c.config_json || '{}');
  const equipes = JSON.parse(c.equipes_json || '[]');
  const grupos = distribuirGrupos(equipes, cfg.numGrupos);

  const tx = db.transaction(() => {
    db.prepare('DELETE FROM competicoes_partidas WHERE competicao_id = ?').run(c.id);
    const ins = db.prepare(`INSERT INTO competicoes_partidas
      (id, competicao_id, rodada, posicao, equipe_a, equipe_b, vencedor, is_terceiro, grupo)
      VALUES (?, ?, ?, ?, ?, ?, '', 0, ?)`);
    grupos.forEach((eg, gi) => {
      const nomeGrupo = LETRAS_GRUPO[gi];
      const rounds = gerarRoundRobin(eg);
      rounds.forEach((matches, ri) => {
        matches.forEach((m, mi) => ins.run(uid(), c.id, ri + 1, mi, m.a, m.b, nomeGrupo));
      });
    });
    cfg.gruposGerados = true;
    cfg.mataMataGerado = false;
    db.prepare('UPDATE competicoes SET config_json=? WHERE id=?').run(JSON.stringify(cfg), c.id);
  });
  tx();

  const salvas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY grupo, rodada, posicao').all(c.id).map(mapPartida);
  res.json(salvas);
});

/**
 * POST /api/competicoes/:id/gerar-mata-mata
 * ------------------------------------------------------------
 * Converte a fase de grupos em chaves eliminatórias:
 *   1. Valida que TODOS os placares foram lançados
 *   2. Calcula a classificação de cada grupo
 *   3. Extrai os N melhores de cada grupo
 *   4. Gera a primeira rodada do mata-mata + rodadas vazias
 *   5. Adiciona a partida de 3º lugar
 *   6. Marca mataMataGerado = true no config
 */
app.post('/api/competicoes/:id/gerar-mata-mata', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  if (c.tipo !== 'grupos_mata_mata') return res.status(400).json({ erro: 'Competição não é do tipo grupos + mata-mata' });

  const cfg = JSON.parse(c.config_json || '{}');
  if (cfg.mataMataGerado) return res.status(400).json({ erro: 'Mata-mata já foi gerado' });

  // Valida placares
  const todas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ?').all(c.id);
  const grupoMatches = todas.filter(p => p.grupo);
  const semPlacar = grupoMatches.filter(p => p.gols_a === null || p.gols_b === null);
  if (semPlacar.length) {
    return res.status(400).json({ erro: `Ainda faltam ${semPlacar.length} placar(es) de grupo` });
  }

  // Calcula classificação de cada grupo
  const grupos = {};
  grupoMatches.forEach(p => {
    if (!grupos[p.grupo]) grupos[p.grupo] = [];
    grupos[p.grupo].push(p);
  });

  const nomesGrupos = Object.keys(grupos).sort();
  const classificados = [];
  nomesGrupos.forEach((nome, gi) => {
    const idsGrupo = new Set();
    grupos[nome].forEach(p => { idsGrupo.add(p.equipe_a); idsGrupo.add(p.equipe_b); });
    const partidasGrupo = grupos[nome].map(p => ({
      equipe_a: p.equipe_a, equipe_b: p.equipe_b, gols_a: p.gols_a, gols_b: p.gols_b
    }));
    const classif = calcularClassificacaoGrupo(Array.from(idsGrupo), partidasGrupo, cfg);
    for (let i = 0; i < cfg.classificadosPorGrupo; i++) {
      if (classif[i]) {
        classificados.push({ grupoIdx: gi, posicao: i + 1, equipeId: classif[i].equipeId });
      }
    }
  });

  const confrontos = gerarPrimeiraRodadaMataMata(classificados, cfg.numGrupos, cfg.classificadosPorGrupo);

  const tx = db.transaction(() => {
    // Apaga qualquer mata-mata anterior (grupo='')
    db.prepare("DELETE FROM competicoes_partidas WHERE competicao_id = ? AND grupo = ''").run(c.id);

    const ins = db.prepare(`INSERT INTO competicoes_partidas
      (id, competicao_id, rodada, posicao, equipe_a, equipe_b, vencedor, is_terceiro, grupo)
      VALUES (?, ?, ?, ?, ?, ?, '', 0, ?)`);

    // Primeira rodada (com os classificados)
    confrontos.forEach((cf, i) => ins.run(uid(), c.id, 1, i, cf.a || '', cf.b || '', ''));

    // Rodadas seguintes (vazias)
    let n = confrontos.length;
    let r = 2;
    while (n > 1) {
      n = n / 2;
      for (let i = 0; i < n; i++) {
        ins.run(uid(), c.id, r, i, '', '', '');
      }
      r++;
    }
    // Partida de 3º lugar
    if (confrontos.length >= 2) {
      ins.run(uid(), c.id, r, 0, '', '', '');
      const ultima = db.prepare("SELECT id FROM competicoes_partidas WHERE competicao_id=? AND grupo='' ORDER BY rowid DESC LIMIT 1").get(c.id);
      db.prepare("UPDATE competicoes_partidas SET is_terceiro=1 WHERE id=?").run(ultima.id);
    }

    cfg.mataMataGerado = true;
    db.prepare('UPDATE competicoes SET config_json=? WHERE id=?').run(JSON.stringify(cfg), c.id);
  });
  tx();

  const salvas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY grupo, rodada, posicao').all(c.id).map(mapPartida);
  res.json(salvas);
});

// Excluir competição (só responsável, cascade apaga partidas)
app.delete('/api/competicoes/:id', auth, bloquearAdminGeral, exigirPapel('responsavel'), (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  db.prepare('DELETE FROM competicoes WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});


// ============================================================
// AUDITORIA
// ============================================================

/**
 * GET /api/auditoria
 * ------------------------------------------------------------
 * Lista os registros de auditoria da org.
 * Suporta filtros opcionais via query string:
 *   ?usuario=Nome  ?entidade=jogo  ?de=YYYY-MM-DD  ?ate=YYYY-MM-DD
 * Limite fixo de 500 registros mais recentes.
 */
app.get('/api/auditoria', auth, exigirPapel('responsavel', 'admin_geral'), (req, res) => {
  const orgId = req.user.papel === 'admin_geral'
    ? (req.query.orgId || req.user.org_id)
    : req.user.org_id;
  if (!orgId) return res.json([]);
  const where = ['org_id = ?'];
  const params = [orgId];
  if (req.query.usuario) { where.push('usuario_nome LIKE ?'); params.push('%' + req.query.usuario + '%'); }
  if (req.query.entidade) { where.push('entidade = ?'); params.push(req.query.entidade); }
  if (req.query.de) { where.push('criado_em >= ?'); params.push(req.query.de); }
  if (req.query.ate) { where.push('criado_em <= ?'); params.push(req.query.ate); }
  const sql = `SELECT * FROM auditoria WHERE ${where.join(' AND ')} ORDER BY criado_em DESC LIMIT 500`;
  res.json(db.prepare(sql).all(...params));
});


// ============================================================
// CLASSIFICAÇÃO GERAL (usada pelo admin para ver o ranking)
// ============================================================
app.get('/api/classificacao', auth, (req, res) => {
  const orgId = req.user.papel === 'admin_geral'
    ? (req.query.orgId || req.user.org_id)
    : req.user.org_id;
  if (!orgId) return res.json([]);

  const equipes = db.prepare('SELECT id, nome, responsavel FROM equipes WHERE org_id = ?').all(orgId);
  const jogos = db.prepare('SELECT * FROM jogos WHERE org_id = ?').all(orgId).map(mapJogo);
  const penalidades = db.prepare('SELECT equipe_id, pontos FROM penalidades WHERE org_id = ?').all(orgId);
  const competicoes = db.prepare('SELECT * FROM competicoes WHERE org_id = ?').all(orgId);

  const mapa = new Map();
  equipes.forEach(e => mapa.set(e.id, { equipe: e, pontos: 0, penal: 0, jogos: 0 }));

  // Soma pontos dos jogos por posição
  jogos.forEach(j => {
    (j.participantes || []).forEach(eid => {
      const item = mapa.get(eid);
      if (!item) return;
      item.jogos++;
      const pid = j.resultados[eid];
      const pos = j.posicoes.find(p => p.id === pid);
      if (pos) item.pontos += Number(pos.pontos) || 0;
    });
  });

  // Soma pontos das competições (só partidas do mata-mata)
  // Soma pontos das competições
competicoes.forEach(c => {
  const pts = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ?').all(c.id).map(mapPartida);

  // -------- Personalizado: usa os blocos "eh_final" e "eh_terceiro" --------
  if (c.tipo === 'personalizado') {
    const blocos = db.prepare('SELECT * FROM competicoes_blocos WHERE competicao_id = ?').all(c.id);
    const blocoFinal = blocos.find(b => b.eh_final);
    const blocoTerceiro = blocos.find(b => b.eh_terceiro);

    if (blocoFinal) {
      const finais = pts
        .filter(p => p.blocoId === blocoFinal.id && p.vencedor && p.equipeA && p.equipeB)
        .sort((a, b) => (b.posicao || 0) - (a.posicao || 0));
      const final = finais[0];
      if (final) {
        const perd = final.vencedor === final.equipeA ? final.equipeB : final.equipeA;
        const v = mapa.get(final.vencedor);
        const p2 = mapa.get(perd);
        if (v) { v.pontos += Number(c.pontos_1) || 0; v.jogos++; }
        if (p2) { p2.pontos += Number(c.pontos_2) || 0; p2.jogos++; }
      }
    }
    if (blocoTerceiro) {
      const terceiros = pts
        .filter(p => p.blocoId === blocoTerceiro.id && p.vencedor)
        .sort((a, b) => (b.posicao || 0) - (a.posicao || 0));
      const terc = terceiros[0];
      if (terc) {
        const t3 = mapa.get(terc.vencedor);
        if (t3) { t3.pontos += Number(c.pontos_3) || 0; t3.jogos++; }
      }
    }
    return; // não usa a lógica antiga
  }

  // -------- Mata-mata e grupos + mata-mata: lógica antiga --------
  const principais = pts.filter(p => !p.isTerceiro && !p.grupo);
  const terc = pts.find(p => p.isTerceiro && !p.grupo);
  const maxR = principais.length ? Math.max(...principais.map(p => p.rodada)) : 0;
  const final = principais.find(p => p.rodada === maxR && p.vencedor && p.equipeA && p.equipeB);
  if (final) {
    const perd = final.vencedor === final.equipeA ? final.equipeB : final.equipeA;
    const v = mapa.get(final.vencedor);
    const p2 = mapa.get(perd);
    if (v) { v.pontos += Number(c.pontos_1) || 0; v.jogos++; }
    if (p2) { p2.pontos += Number(c.pontos_2) || 0; p2.jogos++; }
  }
  if (terc && terc.vencedor) {
    const t3 = mapa.get(terc.vencedor);
    if (t3) { t3.pontos += Number(c.pontos_3) || 0; t3.jogos++; }
  }
});

  // Subtrai penalidades
  penalidades.forEach(p => {
    const item = mapa.get(p.equipe_id);
    if (item) item.penal += Number(p.pontos) || 0;
  });

  const lista = Array.from(mapa.values())
    .map(c => ({ equipe: c.equipe, pontos: c.pontos, penal: c.penal, jogos: c.jogos, total: c.pontos - c.penal }))
    .sort((a, b) => b.total - a.total || a.equipe.nome.localeCompare(b.equipe.nome, 'pt-BR'));
  res.json(lista);
});
// ============================================================
// COMPETIÇÕES PERSONALIZADAS — blocos e partidas editáveis
// ============================================================

function classificarBloco(partidas, cfg) {
  const ptsV = Number(cfg?.pontosVitoria) || 3;
  const ptsE = Number(cfg?.pontosEmpate) || 1;
  const idsSet = new Set();
  partidas.forEach(p => {
    if (p.equipe_a) idsSet.add(p.equipe_a);
    if (p.equipe_b) idsSet.add(p.equipe_b);
  });
  const mapa = new Map();
  Array.from(idsSet).forEach(eid =>
    mapa.set(eid, { id: eid, P:0,V:0,E:0,D:0,GP:0,GC:0,SG:0,PTS:0 })
  );
  partidas.forEach(p => {
    if (!p.equipe_a || !p.equipe_b) return;
    if (p.gols_a === null || p.gols_b === null) return;
    const a = mapa.get(p.equipe_a), b = mapa.get(p.equipe_b);
    if (!a || !b) return;
    a.P++; b.P++;
    a.GP += p.gols_a; a.GC += p.gols_b;
    b.GP += p.gols_b; b.GC += p.gols_a;
    if (p.gols_a > p.gols_b) { a.V++; a.PTS += ptsV; b.D++; }
    else if (p.gols_a < p.gols_b) { b.V++; b.PTS += ptsV; a.D++; }
    else { a.E++; b.E++; a.PTS += ptsE; b.PTS += ptsE; }
  });
  return Array.from(mapa.values())
    .map(x => ({ ...x, SG: x.GP - x.GC }))
    .sort((x, y) => y.PTS - x.PTS || y.SG - x.SG || y.GP - x.GP);
}

function mapBloco(row) {
  let cfg = {};
  try { cfg = JSON.parse(row.config_json || '{}'); } catch {}
  return {
    id: row.id,
    competicaoId: row.competicao_id,
    nome: row.nome,
    tipo: row.tipo,
    ordem: row.ordem || 0,
    ehFinal: !!row.eh_final,
    ehTerceiro: !!row.eh_terceiro,
    config: cfg
  };
}
/* Calcula a classificação de um bloco tipo grupo/repescagem */
function classificarBloco(partidas, cfg) {
  const pontosV = Number(cfg?.pontosVitoria) || 3;
  const pontosE = Number(cfg?.pontosEmpate) || 1;

  const idsSet = new Set();
  partidas.forEach(p => {
    if (p.equipe_a) idsSet.add(p.equipe_a);
    if (p.equipe_b) idsSet.add(p.equipe_b);
  });

  const mapa = new Map();
  Array.from(idsSet).forEach(eid =>
    mapa.set(eid, { id: eid, P:0, V:0, E:0, D:0, GP:0, GC:0, SG:0, PTS:0 })
  );

  partidas.forEach(p => {
    if (!p.equipe_a || !p.equipe_b) return;
    if (p.gols_a === null || p.gols_b === null) return;
    const a = mapa.get(p.equipe_a), b = mapa.get(p.equipe_b);
    if (!a || !b) return;
    a.P++; b.P++;
    a.GP += p.gols_a; a.GC += p.gols_b;
    b.GP += p.gols_b; b.GC += p.gols_a;
    if (p.gols_a > p.gols_b) { a.V++; a.PTS += pontosV; b.D++; }
    else if (p.gols_a < p.gols_b) { b.V++; b.PTS += pontosV; a.D++; }
    else { a.E++; b.E++; a.PTS += pontosE; b.PTS += pontosE; }
  });

  return Array.from(mapa.values())
    .map(x => ({ ...x, SG: x.GP - x.GC }))
    .sort((x, y) => y.PTS - x.PTS || y.SG - x.SG || y.GP - x.GP);
}

/* -------- Blocos: CRUD -------- */

// POST /api/competicoes/:id/blocos
app.post('/api/competicoes/:id/blocos', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  if (c.tipo !== 'personalizado') return res.status(400).json({ erro: 'Competição não é personalizada' });

  const { nome, tipo } = req.body || {};
  if (!nome || !nome.trim()) return res.status(400).json({ erro: 'Nome do bloco é obrigatório' });
  const tipoFinal =
  tipo === 'grupo'      ? 'grupo' :
  tipo === 'repescagem' ? 'repescagem' :
                          'eliminatoria';
  const id = uid();

  // Coloca no final da ordem
  const max = db.prepare('SELECT COALESCE(MAX(ordem), -1) AS m FROM competicoes_blocos WHERE competicao_id = ?').get(c.id).m;
  db.prepare(`INSERT INTO competicoes_blocos (id, competicao_id, nome, tipo, ordem)
              VALUES (?, ?, ?, ?, ?)`).run(id, c.id, nome.trim(), tipoFinal, max + 1);

  res.status(201).json(mapBloco(db.prepare('SELECT * FROM competicoes_blocos WHERE id = ?').get(id)));
});

// PUT /api/competicoes/:id/blocos/:bid
app.put('/api/competicoes/:id/blocos/:bid', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });

  const b = db.prepare('SELECT * FROM competicoes_blocos WHERE id = ? AND competicao_id = ?').get(req.params.bid, c.id);
  if (!b) return res.status(404).json({ erro: 'Bloco não encontrado' });

  const { nome, tipo, ehFinal, ehTerceiro, config } = req.body || {};
  const nomeFinal = nome && nome.trim() ? nome.trim() : b.nome;
  const tipoFinal =
  (tipo === 'grupo' || tipo === 'eliminatoria' || tipo === 'repescagem') ? tipo : b.tipo;

  db.prepare(`UPDATE competicoes_blocos
              SET nome=?, tipo=?, eh_final=?, eh_terceiro=?, config_json=?
              WHERE id=?`)
    .run(
      nomeFinal, tipoFinal,
      ehFinal === undefined ? b.eh_final : (ehFinal ? 1 : 0),
      ehTerceiro === undefined ? b.eh_terceiro : (ehTerceiro ? 1 : 0),
      config ? JSON.stringify(config) : b.config_json,
      b.id
    );
  res.json(mapBloco(db.prepare('SELECT * FROM competicoes_blocos WHERE id = ?').get(b.id)));
});

// DELETE /api/competicoes/:id/blocos/:bid
app.delete('/api/competicoes/:id/blocos/:bid', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });

  db.prepare('DELETE FROM competicoes_partidas WHERE bloco_id = ?').run(req.params.bid);
  db.prepare('DELETE FROM competicoes_blocos WHERE id = ? AND competicao_id = ?').run(req.params.bid, c.id);
  res.json({ ok: true });
});

/* -------- Partidas de um bloco: CRUD -------- */

// POST /api/competicoes/:id/blocos/:bid/partidas
app.post('/api/competicoes/:id/blocos/:bid/partidas', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });

  const b = db.prepare('SELECT * FROM competicoes_blocos WHERE id = ? AND competicao_id = ?').get(req.params.bid, c.id);
  if (!b) return res.status(404).json({ erro: 'Bloco não encontrado' });

  const { equipeA = '', equipeB = '' } = req.body || {};
  const max = db.prepare('SELECT COALESCE(MAX(posicao), -1) AS m FROM competicoes_partidas WHERE bloco_id = ?').get(b.id).m;
  const id = uid();

  db.prepare(`INSERT INTO competicoes_partidas
    (id, competicao_id, rodada, posicao, equipe_a, equipe_b, vencedor, is_terceiro, grupo, bloco_id)
    VALUES (?, ?, 1, ?, ?, ?, '', 0, '', ?)`)
    .run(id, c.id, max + 1, equipeA, equipeB, b.id);

  res.status(201).json(mapPartida(db.prepare('SELECT * FROM competicoes_partidas WHERE id = ?').get(id)));
});

app.post('/api/competicoes/:id/blocos/:bid/popular-repescagem', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });

  const b = db.prepare('SELECT * FROM competicoes_blocos WHERE id = ? AND competicao_id = ?')
    .get(req.params.bid, c.id);
  if (!b) return res.status(404).json({ erro: 'Bloco não encontrado' });
  if (b.tipo !== 'repescagem') return res.status(400).json({ erro: 'Só funciona em bloco tipo Repescagem' });

  const { posicao = 2 } = req.body || {};

  const grupos = db.prepare(
    "SELECT * FROM competicoes_blocos WHERE competicao_id = ? AND tipo = 'grupo' ORDER BY ordem"
  ).all(c.id);
  if (!grupos.length) return res.status(400).json({ erro: 'Crie pelo menos um bloco de Grupo' });

  const ids = [];
  let faltamPlacar = 0;
  grupos.forEach(g => {
    const partidas = db.prepare('SELECT * FROM competicoes_partidas WHERE bloco_id = ?').all(g.id);
    const classif = classificarBloco(partidas, JSON.parse(g.config_json || '{}'));
    if (classif[posicao - 1]) ids.push(classif[posicao - 1].id);
    else faltamPlacar++;
  });

  if (faltamPlacar === grupos.length) {
    return res.status(400).json({ erro: 'Lance os placares dos grupos primeiro' });
  }
  if (ids.length < 2) {
    return res.status(400).json({ erro: 'Precisa de pelo menos 2 equipes para a repescagem' });
  }

  // Round-robin
  const lista = [...ids];
  if (lista.length % 2 === 1) lista.push(null);
  const n = lista.length;
  const half = n / 2;
  const confrontos = [];
  for (let r = 0; r < n - 1; r++) {
    for (let i = 0; i < half; i++) {
      const a = lista[i], bb = lista[n - 1 - i];
      if (a !== null && bb !== null) {
        confrontos.push(r % 2 === 0 ? { a, b: bb } : { a: bb, b: a });
      }
    }
    const fixed = lista[0];
    const rest = lista.slice(1);
    rest.unshift(rest.pop());
    lista.length = 0;
    lista.push(fixed, ...rest);
  }

  const insert = db.prepare(`
    INSERT INTO competicoes_partidas
      (id, competicao_id, rodada, posicao, equipe_a, equipe_b, vencedor, is_terceiro, grupo, bloco_id)
    VALUES (?, ?, 1, ?, ?, ?, '', 0, '', ?)
  `);
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM competicoes_partidas WHERE bloco_id = ?').run(b.id);
    confrontos.forEach((cf, i) => insert.run(uid(), c.id, i, cf.a, cf.b, b.id));
  });
  tx();

  res.json({ ok: true, equipes: ids.length, criados: confrontos.length });
});


app.post('/api/competicoes/:id/blocos/:bid/gerar-round-robin', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });

  const b = db.prepare('SELECT * FROM competicoes_blocos WHERE id = ? AND competicao_id = ?')
    .get(req.params.bid, c.id);
  if (!b) return res.status(404).json({ erro: 'Bloco não encontrado' });
  if (b.tipo !== 'grupo') return res.status(400).json({ erro: 'Só funciona em blocos tipo Grupo' });

  const { equipeIds } = req.body || {};
  if (!Array.isArray(equipeIds) || equipeIds.length < 2) {
    return res.status(400).json({ erro: 'Selecione ao menos 2 equipes' });
  }

  const inscritas = JSON.parse(c.equipes_json || '[]');
  for (const id of equipeIds) {
    if (!inscritas.includes(id)) {
      return res.status(400).json({ erro: 'Equipe não inscrita nesta competição' });
    }
  }

  // Gera round-robin (método do círculo)
  const lista = [...equipeIds];
  if (lista.length % 2 === 1) lista.push(null);
  const n = lista.length;
  const half = n / 2;
  const confrontos = [];

  for (let r = 0; r < n - 1; r++) {
    for (let i = 0; i < half; i++) {
      const a = lista[i];
      const bb = lista[n - 1 - i];
      if (a !== null && bb !== null) {
        confrontos.push(r % 2 === 0 ? { a, b: bb } : { a: bb, b: a });
      }
    }
    const fixed = lista[0];
    const rest = lista.slice(1);
    rest.unshift(rest.pop());
    lista.length = 0;
    lista.push(fixed, ...rest);
  }

  const insert = db.prepare(`
    INSERT INTO competicoes_partidas
      (id, competicao_id, rodada, posicao, equipe_a, equipe_b, vencedor, is_terceiro, grupo, bloco_id)
    VALUES (?, ?, 1, ?, ?, ?, '', 0, '', ?)
  `);

  const tx = db.transaction(() => {
    db.prepare('DELETE FROM competicoes_partidas WHERE bloco_id = ?').run(b.id);
    confrontos.forEach((cf, i) => {
      insert.run(uid(), c.id, i, cf.a, cf.b, b.id);
    });
  });
  tx();

  res.json({ ok: true, criados: confrontos.length });
});

// PUT /api/competicoes/:id/partidas/:pid  (edita equipes do confronto)
app.put('/api/competicoes/:id/partidas/:pid', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });

  const p = db.prepare('SELECT * FROM competicoes_partidas WHERE id = ? AND competicao_id = ?').get(req.params.pid, c.id);
  if (!p) return res.status(404).json({ erro: 'Partida não encontrada' });

  const { equipeA, equipeB } = req.body || {};
  const a = equipeA === undefined ? p.equipe_a : equipeA;
  const b = equipeB === undefined ? p.equipe_b : equipeB;

  // Limpa vencedor se a equipe mudou
  let venc = p.vencedor;
  if ((p.equipe_a !== a || p.equipe_b !== b) && venc && venc !== a && venc !== b) {
    venc = '';
  }

  db.prepare('UPDATE competicoes_partidas SET equipe_a=?, equipe_b=?, vencedor=? WHERE id=?')
    .run(a, b, venc, p.id);

  res.json(mapPartida(db.prepare('SELECT * FROM competicoes_partidas WHERE id = ?').get(p.id)));
});

// DELETE /api/competicoes/:id/partidas/:pid
app.delete('/api/competicoes/:id/partidas/:pid', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });

  const r = db.prepare('DELETE FROM competicoes_partidas WHERE id = ? AND competicao_id = ?').run(req.params.pid, c.id);
  if (r.changes === 0) return res.status(404).json({ erro: 'Partida não encontrada' });
  res.json({ ok: true });
});

/* Calcula a classificação de um bloco tipo grupo/repescagem */
function classificarBloco(partidas, cfg) {
  const pontosV = Number(cfg?.pontosVitoria) || 3;
  const pontosE = Number(cfg?.pontosEmpate) || 1;

  const idsSet = new Set();
  partidas.forEach(p => {
    if (p.equipe_a) idsSet.add(p.equipe_a);
    if (p.equipe_b) idsSet.add(p.equipe_b);
  });

  const mapa = new Map();
  Array.from(idsSet).forEach(eid =>
    mapa.set(eid, { id: eid, P:0, V:0, E:0, D:0, GP:0, GC:0, SG:0, PTS:0 })
  );

  partidas.forEach(p => {
    if (!p.equipe_a || !p.equipe_b) return;
    if (p.gols_a === null || p.gols_b === null) return;
    const a = mapa.get(p.equipe_a), b = mapa.get(p.equipe_b);
    if (!a || !b) return;
    a.P++; b.P++;
    a.GP += p.gols_a; a.GC += p.gols_b;
    b.GP += p.gols_b; b.GC += p.gols_a;
    if (p.gols_a > p.gols_b) { a.V++; a.PTS += pontosV; b.D++; }
    else if (p.gols_a < p.gols_b) { b.V++; b.PTS += pontosV; a.D++; }
    else { a.E++; b.E++; a.PTS += pontosE; b.PTS += pontosE; }
  });

  return Array.from(mapa.values())
    .map(x => ({ ...x, SG: x.GP - x.GC }))
    .sort((x, y) => y.PTS - x.PTS || y.SG - x.SG || y.GP - x.GP);
}
/* ============================================================
   POST /api/competicoes/:id/preencher-mata-mata
   ------------------------------------------------------------
   Calcula os N primeiros de cada bloco tipo 'grupo' e preenche
   o PRÓXIMO bloco tipo 'eliminatoria' com o cruzamento olímpico.
   ============================================================ */
app.post('/api/competicoes/:id/preencher-mata-mata', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  if (c.tipo !== 'personalizado') return res.status(400).json({ erro: 'Só para competições personalizadas' });

  const grupos = db.prepare(
    "SELECT * FROM competicoes_blocos WHERE competicao_id = ? AND tipo = 'grupo' ORDER BY ordem"
  ).all(c.id);
  if (grupos.length < 2) return res.status(400).json({ erro: 'Crie pelo menos 2 blocos de Grupo' });

  const repescagem = db.prepare(
    "SELECT * FROM competicoes_blocos WHERE competicao_id = ? AND tipo = 'repescagem' ORDER BY ordem LIMIT 1"
  ).get(c.id);

  // Auto-detecção:
  //   - Se tem repescagem: 1º de cada grupo + 1º da repescagem
  //   - Se não tem: usa classificadosPorGrupo do body (padrão 1)
  const { classificadosPorGrupo: cpgBody = 1 } = req.body || {};
  const K = repescagem ? 1 : cpgBody;

  // Coleta os K primeiros de cada grupo
  const classificados = [];
  for (const g of grupos) {
    const partidas = db.prepare('SELECT * FROM competicoes_partidas WHERE bloco_id = ?').all(g.id);
    const classif = classificarBloco(partidas, JSON.parse(g.config_json || '{}'));
    const top = classif.slice(0, K);
    if (top.length < K) {
      return res.status(400).json({ erro: `Lance os placares do grupo "${g.nome}" primeiro` });
    }
    top.forEach(x => classificados.push(x.id));
  }

  // Adiciona o vencedor da repescagem
  if (repescagem) {
    const partidas = db.prepare('SELECT * FROM competicoes_partidas WHERE bloco_id = ?').all(repescagem.id);
    const classif = classificarBloco(partidas, JSON.parse(repescagem.config_json || '{}'));
    if (!classif[0]) {
      return res.status(400).json({ erro: 'Lance os placares da repescagem primeiro' });
    }
    classificados.push(classif[0].id);
  }

  const N = classificados.length;
  if (N < 2) return res.status(400).json({ erro: 'Poucos classificados para gerar o mata-mata' });

  // Cruzamento olímpico: T1 × TN, T2 × T(N-1), ...
  const confrontos = [];
  for (let i = 0; i < Math.floor(N / 2); i++) {
    confrontos.push({ a: classificados[i], b: classificados[N - 1 - i] });
  }
  // Se N ímpar, o time do meio ganha bye
  if (N % 2 === 1) {
    confrontos.push({ a: classificados[Math.floor(N / 2)], b: null });
  }

  // Acha o próximo bloco eliminatório
  const proximo = db.prepare(`
    SELECT * FROM competicoes_blocos
    WHERE competicao_id = ?
      AND tipo = 'eliminatoria'
      AND ordem > (SELECT MAX(ordem) FROM competicoes_blocos WHERE competicao_id = ? AND tipo IN ('grupo','repescagem'))
    ORDER BY ordem LIMIT 1
  `).get(c.id, c.id);
  if (!proximo) return res.status(400).json({ erro: 'Crie um bloco Eliminatório depois dos grupos/repescagem' });

  db.prepare('DELETE FROM competicoes_partidas WHERE bloco_id = ?').run(proximo.id);

  const insert = db.prepare(`
    INSERT INTO competicoes_partidas
      (id, competicao_id, rodada, posicao, equipe_a, equipe_b, vencedor, is_terceiro, grupo, bloco_id)
    VALUES (?, ?, 1, ?, ?, ?, '', 0, '', ?)
  `);
  const tx = db.transaction(() => {
    confrontos.forEach((cf, i) => insert.run(uid(), c.id, i, cf.a || '', cf.b || '', proximo.id));
  });
  tx();

  res.json({ ok: true, classificados: N, confrontos: confrontos.length });
});
// ============================================================
// FALLBACK SPA
// ------------------------------------------------------------
// IMPORTANTE: essas rotas PRECISAM vir depois de todas as rotas
// /api/*, senão o Express vai interceptar as chamadas de API.
//
// - /admin     → serve o painel de administração
// - qualquer outra rota → serve a tela pública
// ============================================================
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));


// ============================================================
// INICIALIZAÇÃO DO SERVIDOR
// ------------------------------------------------------------
// Escuta em 0.0.0.0 para aceitar conexões de qualquer IP
// (necessário para funcionar dentro de containers).
// ============================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🌱 CompAct Jr. rodando em http://0.0.0.0:${PORT}`);
});