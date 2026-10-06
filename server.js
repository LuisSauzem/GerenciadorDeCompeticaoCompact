const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo-em-producao';

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const uid = () => crypto.randomBytes(8).toString('hex');
const slugify = s => String(s).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
  .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);

/* ============ AUTH ============ */
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

function exigirPapel(...papeis) {
  return (req, res, next) => {
    if (!papeis.includes(req.user.papel)) {
      return res.status(403).json({ erro: 'Sem permissão' });
    }
    next();
  };
}

function exigirOrgPropria(req, orgId) {
  if (req.user.papel === 'admin_geral') return true;
  return req.user.org_id === orgId;
}

function bloquearAdminGeral(req, res, next) {
  if (req.user.papel === 'admin_geral') {
    return res.status(403).json({ erro: 'Admin geral não pode executar essa ação' });
  }
  next();
}


/* Auditoria — registra alteração de placar/vencedor */
function registrarAuditoria({ orgId, user, entidade, entidadeId, entidadeNome, acao, valorAntigo, valorNovo }) {
  db.prepare(`INSERT INTO auditoria
    (org_id, usuario_id, usuario_nome, entidade, entidade_id, entidade_nome, acao, valor_antigo, valor_novo)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(orgId, user.id, user.nome, entidade, entidadeId, entidadeNome || '',
         acao, JSON.stringify(valorAntigo ?? null), JSON.stringify(valorNovo ?? null));
}

/* ============ LOGIN ============ */
app.post('/api/auth/login', (req, res) => {
  const { usuario, senha } = req.body || {};
  if (!usuario || !senha) return res.status(400).json({ erro: 'Informe usuário e senha' });
  const u = db.prepare(`SELECT u.*, o.nome AS org_nome, o.slug AS org_slug
                        FROM usuarios u LEFT JOIN organizacoes o ON o.id = u.org_id
                        WHERE u.usuario = ?`).get(usuario);
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

/* ============ ME ============ */
app.get('/api/me', auth, (req, res) => {
  const org = req.user.org_id
    ? db.prepare('SELECT id, nome, slug, cor, emoji FROM organizacoes WHERE id = ?').get(req.user.org_id)
    : null;
  res.json({ ...req.user, org });
});


/* ============ TROCAR PRÓPRIA SENHA ============ */
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

/* ============ ROTAS PÚBLICAS ============ */
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

app.get('/api/publico/orgs/:slug', (req, res) => {
  const org = db.prepare('SELECT id, nome, slug, cor, emoji, imagem FROM organizacoes WHERE slug = ? AND ativo = 1').get(req.params.slug);
  if (!org) return res.status(404).json({ erro: 'Organização não encontrada' });

  const equipes = db.prepare('SELECT id, nome, responsavel FROM equipes WHERE org_id = ? ORDER BY nome').all(org.id);
  const jogos = db.prepare('SELECT * FROM jogos WHERE org_id = ? AND secreto = 0 ORDER BY nome').all(org.id);
  const penalidades = db.prepare('SELECT equipe_id, pontos FROM penalidades WHERE org_id = ?').all(org.id);
  const competicoes = db.prepare('SELECT * FROM competicoes WHERE org_id = ? AND secreto = 0').all(org.id);

  // Calcula pontuação
  const mapa = new Map();
  equipes.forEach(e => mapa.set(e.id, { id: e.id, nome: e.nome, pontos: 0, penal: 0 }));

  jogos.forEach(j => {
    const part = JSON.parse(j.participantes_json || '[]');
    const pos = JSON.parse(j.posicoes_json || '[]');
    const res = JSON.parse(j.resultados_json || '{}');
    part.forEach(eid => {
      const item = mapa.get(eid);
      if (!item) return;
      const pid = res[eid];
      const p = pos.find(x => x.id === pid);
      if (p) item.pontos += Number(p.pontos) || 0;
    });
  });

  competicoes.forEach(c => {
    const partidas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY rodada, posicao').all(c.id);
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

  penalidades.forEach(p => {
    const item = mapa.get(p.equipe_id);
    if (item) item.penal += Number(p.pontos) || 0;
  });

  const classificacao = Array.from(mapa.values())
    .map(c => ({ ...c, total: c.pontos - c.penal }))
    .sort((a, b) => b.total - a.total || a.nome.localeCompare(b.nome, 'pt-BR'));

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
        grupo: p.grupo || '',
        golsA: (p.gols_a === null || p.gols_a === undefined) ? null : p.gols_a,
        golsB: (p.gols_b === null || p.gols_b === undefined) ? null : p.gols_b
      }));

      // Se for grupos, calcula classificação de cada grupo
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
        grupos: gruposOut
      };
    })
  });
});

/* ============ ORGANIZAÇÕES (admin_geral) ============ */
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

app.post('/api/orgs', auth, exigirPapel('admin_geral'), (req, res) => {
  const { nome, cor, emoji } = req.body || {};
  if (!nome || !nome.trim()) return res.status(400).json({ erro: 'Nome é obrigatório' });
  let slug = slugify(nome);
  if (!slug) slug = 'org-' + uid().slice(0, 6);
  // Garante unicidade
  let baseSlug = slug, i = 1;
  while (db.prepare('SELECT id FROM organizacoes WHERE slug = ?').get(slug)) {
    slug = baseSlug + '-' + i++; if (i > 50) return res.status(400).json({ erro: 'Não foi possível gerar slug' });
  }
  const id = uid();
  db.prepare('INSERT INTO organizacoes (id, nome, slug, cor, emoji) VALUES (?, ?, ?, ?, ?)')
    .run(id, nome.trim(), slug, cor || '#0ea5e9', emoji || '🏆');
  res.status(201).json(db.prepare('SELECT * FROM organizacoes WHERE id = ?').get(id));
});

app.put('/api/orgs/:id', auth, exigirPapel('admin_geral'), (req, res) => {
  const { nome, cor, emoji, ativo } = req.body || {};
  const org = db.prepare('SELECT * FROM organizacoes WHERE id = ?').get(req.params.id);
  if (!org) return res.status(404).json({ erro: 'Organização não encontrada' });
  db.prepare('UPDATE organizacoes SET nome=?, cor=?, emoji=?, ativo=? WHERE id=?')
    .run(nome?.trim() || org.nome, cor ?? org.cor, emoji ?? org.emoji,
         ativo === undefined ? org.ativo : (ativo ? 1 : 0), req.params.id);
  res.json(db.prepare('SELECT * FROM organizacoes WHERE id = ?').get(req.params.id));
});

app.delete('/api/orgs/:id', auth, exigirPapel('admin_geral'), (req, res) => {
  const r = db.prepare('DELETE FROM organizacoes WHERE id = ?').run(req.params.id);
  if (r.changes === 0) return res.status(404).json({ erro: 'Organização não encontrada' });
  res.json({ ok: true });
});

/* ============ USUÁRIOS ============ */
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

  // Só admin_geral pode criar 'responsavel'. Responsável só cria 'organizador'.
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

/* ============ EQUIPES ============ */
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

/* ============ JOGOS ============ */
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

app.put('/api/jogos/:id/revelar', auth, bloquearAdminGeral, exigirPapel('responsavel'), (req, res) => {
  const j = db.prepare('SELECT * FROM jogos WHERE id = ?').get(req.params.id);
  if (!j) return res.status(404).json({ erro: 'Jogo não encontrado' });
  if (!exigirOrgPropria(req, j.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  db.prepare('UPDATE jogos SET secreto=0 WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

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

/* ============ PENALIDADES ============ */
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

/* ============ COMPETIÇÕES (Mata-Mata) ============ */
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
    golsA: (row.gols_a === null || row.gols_a === undefined) ? null : row.gols_a,
    golsB: (row.gols_b === null || row.gols_b === undefined) ? null : row.gols_b
  };
}

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

function gerarChave(equipesIds) {
  const arr = [...equipesIds];
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
      const venc = (a && !b) ? a : (!a && b) ? b : '';
      todas.push({ rodada, posicao: i, equipe_a: a, equipe_b: b, vencedor: venc, is_terceiro: 0 });
    }
    timesRodada = new Array(qtd).fill('');
    rodada++;
  }
  if (arr.length >= 4) {
    todas.push({ rodada, posicao: 0, equipe_a: '', equipe_b: '', vencedor: '', is_terceiro: 1 });
  }
  return todas;
}

/* ============================================================
   FASE DE GRUPOS — geração, classificação e mata-mata
   ============================================================ */

const LETRAS_GRUPO = 'ABCDEFGHIJKLMNOP'.split('');

/* Distribui times em grupos, round-robin (equilibra tamanhos) */
function distribuirGrupos(equipes, numGrupos) {
  const arr = [...equipes];
  // Fisher-Yates shuffle
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  const grupos = Array.from({ length: numGrupos }, () => []);
  arr.forEach((eq, i) => { grupos[i % numGrupos].push(eq); });
  return grupos;
}

/* Gera todos-contra-todos de um grupo (método do círculo) */
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
        matches.push(r % 2 === 0 ? { a, b } : { a: b, b: a });
      }
    }
    rounds.push(matches);

    // rotaciona mantendo o primeiro fixo
    const fixed = list[0];
    const rest = list.slice(1);
    rest.unshift(rest.pop());
    list.length = 0;
    list.push(fixed, ...rest);
  }
  return rounds;
}

/* Calcula a classificação de um grupo a partir das partidas */
function calcularClassificacaoGrupo(equipesGrupo, partidasGrupo, cfg) {
  const ptsV = Number(cfg.pontosVitoria) || 3;
  const ptsE = Number(cfg.pontosEmpate) || 1;

  const mapa = new Map();
  equipesGrupo.forEach(eid => mapa.set(eid, {
    equipeId: eid, P: 0, V: 0, E: 0, D: 0, GP: 0, GC: 0, SG: 0, PTS: 0
  }));

  partidasGrupo.forEach(p => {
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

/* Monta os confrontos iniciais do mata-mata a partir dos classificados.
   Se o número não for potência de 2, preenche com byes. */
function gerarPrimeiraRodadaMataMata(classificados, numGrupos, classificadosPorGrupo) {
  // Ordena: 1ºA, 1ºB, 2ºA, 2ºB, ... (primeiro os 1ºs, depois os 2ºs, etc.)
  const porPos = [];
  for (let pos = 1; pos <= classificadosPorGrupo; pos++) {
    for (let g = 0; g < numGrupos; g++) {
      const item = classificados.find(c => c.grupoIdx === g && c.posicao === pos);
      if (item) porPos.push(item.equipeId);
    }
  }

  const n = porPos.length;
  // Próxima potência de 2 ≥ n
  let pot2 = 1;
  while (pot2 < n) pot2 *= 2;

  // Completa com nulls (byes) para chegar em pot2
  const slots = [...porPos];
  while (slots.length < pot2) slots.push(null);

  // Pareamento tipo copa: seed 1 vs seed N, seed 2 vs N-1...
  const confrontos = [];
  for (let i = 0; i < pot2 / 2; i++) {
    confrontos.push({ a: slots[i], b: slots[pot2 - 1 - i] });
  }
  return confrontos;
}


function recomputarChave(partidasTodas) {
  const partidas = partidasTodas.filter(p => !p.grupo);
  const principais = partidas.filter(p => !p.is_terceiro);
  const terceiro = partidas.find(p => p.is_terceiro);

  const porRodada = {};
  principais.forEach(p => {
    if (!porRodada[p.rodada]) porRodada[p.rodada] = [];
    porRodada[p.rodada].push(p);
  });
  const rodadas = Object.keys(porRodada).map(Number).sort((a, b) => a - b);
  rodadas.forEach(r => porRodada[r].sort((a, b) => a.posicao - b.posicao));

  // Loop rodada a rodada, propagando e validando SEM resetar nada de antemão
  for (let i = 0; i < rodadas.length; i++) {
    const matchups = porRodada[rodadas[i]];
    const prevLen = i > 0 ? porRodada[rodadas[i - 1]].length : 0;

    // 1. Se i > 0, propaga os vencedores da rodada anterior para esta
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

        // Só limpa o vencedor se algum dos times realmente mudou
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
        isBye = (!!m.equipe_a) !== (!!m.equipe_b);
      } else {
        isBye = (prevLen % 2 === 1) && isLast;
      }

      if (isBye) {
        // Bye estrutural: único time avança automaticamente
        if (m.equipe_a && !m.equipe_b) m.vencedor = m.equipe_a;
        else if (!m.equipe_a && m.equipe_b) m.vencedor = m.equipe_b;
      } else {
        // Se faltam times, não pode ter vencedor
        if (!m.equipe_a || !m.equipe_b) {
          m.vencedor = '';
        }
        // Se o vencedor não é um dos dois times, limpa
        if (m.vencedor && m.vencedor !== m.equipe_a && m.vencedor !== m.equipe_b) {
          m.vencedor = '';
        }
      }
      if (!m.equipe_a && !m.equipe_b) m.vencedor = '';
    });
  }

  // 3. Disputa de 3º lugar (perdedores das semifinais)
  if (terceiro && rodadas.length >= 2) {
    const semiR = rodadas[rodadas.length - 2];
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

    if (oldA !== perd1 || oldB !== perd2) terceiro.vencedor = '';
    if (terceiro.vencedor && terceiro.vencedor !== perd1 && terceiro.vencedor !== perd2) {
      terceiro.vencedor = '';
    }
    if (!terceiro.vencedor) {
      if (perd1 && !perd2) terceiro.vencedor = perd1;
      else if (!perd1 && perd2) terceiro.vencedor = perd2;
    }
  }

  return partidasTodas;
}

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

    return comp;
  });

  res.json(resultado);
});

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
  const tipoFinal = tipo === 'grupos_mata_mata' ? 'grupos_mata_mata' : 'mata_mata';

  if (tipoFinal === 'mata_mata') {
    const partidas = gerarChave(equipes);
    const tx = db.transaction(() => {
      db.prepare(`INSERT INTO competicoes (id, org_id, nome, tipo, secreto, equipes_json, pontos_1, pontos_2, pontos_3, config_json)
                  VALUES (?, ?, ?, 'mata_mata', ?, ?, ?, ?, ?, '{}')`)
        .run(id, orgId, nome.trim(), secreto ? 1 : 0, JSON.stringify(equipes),
             Number(pontos1) || 0, Number(pontos2) || 0, Number(pontos3) || 0);
      const ins = db.prepare(`INSERT INTO competicoes_partidas
        (id, competicao_id, rodada, posicao, equipe_a, equipe_b, vencedor, is_terceiro)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
      partidas.forEach(p => ins.run(uid(), id, p.rodada, p.posicao, p.equipe_a, p.equipe_b, p.vencedor, p.is_terceiro));
    });
    tx();
  } else {
    // Grupos + Mata-Mata
    const nG = Math.max(2, Math.min(8, Number(numGrupos) || 2));
    const cPG = Math.max(1, Math.min(4, Number(classificadosPorGrupo) || 2));
    if (equipes.length < nG * 2) {
      return res.status(400).json({ erro: `Precisa de ao menos ${nG * 2} equipes para ${nG} grupos` });
    }
    const grupos = distribuirGrupos(equipes, nG);
    const config = {
      numGrupos: nG,
      classificadosPorGrupo: cPG,
      pontosVitoria: Number(pontosVitoria) || 3,
      pontosEmpate: Number(pontosEmpate) || 1,
      gruposGerados: true,
      mataMataGerado: false
    };

    const tx = db.transaction(() => {
      db.prepare(`INSERT INTO competicoes (id, org_id, nome, tipo, secreto, equipes_json, pontos_1, pontos_2, pontos_3, config_json)
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
  }

  const row = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(id);
  const salvas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY grupo, rodada, posicao').all(id).map(mapPartida);
  res.status(201).json(mapCompeticao(row, salvas));
});

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

app.put('/api/competicoes/:id/partidas/:pid/vencedor', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  const { vencedor } = req.body || {};

  const partidas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ? ORDER BY rodada, posicao, id').all(req.params.id);
  const alvo = partidas.find(x => x.id === req.params.pid);
  if (!alvo) return res.status(404).json({ erro: 'Partida não encontrada' });

  const antigoVenc = alvo.vencedor;
  alvo.vencedor = String(vencedor || '');
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

app.put('/api/competicoes/:id/revelar', auth, bloquearAdminGeral, exigirPapel('responsavel'), (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  db.prepare('UPDATE competicoes SET secreto=0 WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

/* === Salvar placar de uma partida de grupo === */
app.put('/api/competicoes/:id/partidas/:pid/placar', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });

  const p = db.prepare('SELECT * FROM competicoes_partidas WHERE id = ? AND competicao_id = ?')
    .get(req.params.pid, c.id);
  if (!p) return res.status(404).json({ erro: 'Partida não encontrada' });
  if (!p.grupo) return res.status(400).json({ erro: 'Só é possível lançar placar em partidas de grupo' });

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

/* === Sortear grupos novamente (só se nenhum placar lançado) === */
app.post('/api/competicoes/:id/sortear-grupos', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  if (c.tipo !== 'grupos_mata_mata') return res.status(400).json({ erro: 'Competição não é do tipo grupos + mata-mata' });

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

/* === Gerar mata-mata depois dos grupos === */
app.post('/api/competicoes/:id/gerar-mata-mata', auth, bloquearAdminGeral, (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  if (c.tipo !== 'grupos_mata_mata') return res.status(400).json({ erro: 'Competição não é do tipo grupos + mata-mata' });

  const cfg = JSON.parse(c.config_json || '{}');
  if (cfg.mataMataGerado) return res.status(400).json({ erro: 'Mata-mata já foi gerado' });

  const todas = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ?').all(c.id);
  const grupoMatches = todas.filter(p => p.grupo);
  const semPlacar = grupoMatches.filter(p => p.gols_a === null || p.gols_b === null);
  if (semPlacar.length) {
    return res.status(400).json({ erro: `Ainda faltam ${semPlacar.length} placar(es) de grupo` });
  }

  // Classificação de cada grupo
  const equipes = JSON.parse(c.equipes_json || '[]');
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
    confrontos.forEach((cf, i) => ins.run(uid(), c.id, 1, i, cf.a || '', cf.b || '', ''));

    // Cria as próximas rodadas (vazias)
    let n = confrontos.length;
    let r = 2;
    while (n > 1) {
      n = n / 2;
      for (let i = 0; i < n; i++) {
        ins.run(uid(), c.id, r, i, '', '', '');
      }
      r++;
    }
    // 3º lugar
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

app.delete('/api/competicoes/:id', auth, bloquearAdminGeral, exigirPapel('responsavel'), (req, res) => {
  const c = db.prepare('SELECT * FROM competicoes WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ erro: 'Competição não encontrada' });
  if (!exigirOrgPropria(req, c.org_id)) return res.status(403).json({ erro: 'Sem permissão' });
  db.prepare('DELETE FROM competicoes WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

/* ============ AUDITORIA ============ */
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

/* ============ CLASSIFICAÇÃO ============ */
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

    competicoes.forEach(c => {
    const pts = db.prepare('SELECT * FROM competicoes_partidas WHERE competicao_id = ?').all(c.id).map(mapPartida);
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

  penalidades.forEach(p => {
    const item = mapa.get(p.equipe_id);
    if (item) item.penal += Number(p.pontos) || 0;
  });

  const lista = Array.from(mapa.values())
    .map(c => ({ equipe: c.equipe, pontos: c.pontos, penal: c.penal, jogos: c.jogos, total: c.pontos - c.penal }))
    .sort((a, b) => b.total - a.total || a.equipe.nome.localeCompare(b.equipe.nome, 'pt-BR'));
  res.json(lista);
});

/* ============ FALLBACK SPA ============ */
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🌱 CompAct Jr. rodando em http://0.0.0.0:${PORT}`);
});