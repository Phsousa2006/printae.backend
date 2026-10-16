const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();

// ---- Segredo do JWT: NUNCA fica no código (o repositório é público) ----
// Defina JWT_SECRET no Render (Environment). Sem ele, usamos um segredo aleatório temporário:
// o site funciona, mas todos precisam fazer login de novo a cada reinicialização.
let JWT_SECRET = String(process.env.JWT_SECRET || '').trim();
if (JWT_SECRET.length < 32) {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  console.warn('ATENÇÃO: JWT_SECRET não definido (ou com menos de 32 caracteres). Usando segredo temporário; defina JWT_SECRET no Render.');
}
const JWT_OPTS = { algorithms: ['HS256'] };

app.disable('x-powered-by');
app.set('trust proxy', 1); // Render fica atrás de proxy: necessário para o IP real (limite de tentativas)

// ---- CORS: só os sites autorizados podem chamar a API pelo navegador ----
// ALLOWED_ORIGINS = endereços do site e do painel, separados por vírgula (sem barra no final).
// Ex.: https://www.printae.com.br,https://printae.com.br
const ORIGENS = String(process.env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim().replace(/\/$/, '')).filter(Boolean);
if (!ORIGENS.length) console.warn('ATENÇÃO: ALLOWED_ORIGINS não definido. A API está aceitando qualquer origem (CORS aberto).');
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || !ORIGENS.length || ORIGENS.includes(origin)) return cb(null, true);
    return cb(null, false);
  }
}));

// ---- Cabeçalhos de segurança ----
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// ---- Tamanho do corpo: 50 MB só para rotas de ADMIN que recebem imagens; o resto aceita pouco ----
const ROTAS_COM_IMAGEM = ['/api/banners', '/api/categorias', '/api/produtos', '/api/configuracoes'];
app.use(ROTAS_COM_IMAGEM, (req, res, next) => {
  if (req.method === 'GET' || req.method === 'DELETE') return next();
  // exige token válido ANTES de aceitar um corpo grande
  const t = (req.headers['authorization'] || '').split(' ')[1];
  jwt.verify(t || '', JWT_SECRET, JWT_OPTS, (err, p) => {
    if (err || !p || typeof p.usuario !== 'string' || p.setup) return res.status(401).json({ error: 'Acesso negado.' });
    express.json({ limit: '50mb' })(req, res, next);
  });
});
app.use(express.json({ limit: '50kb' }));
app.use((err, req, res, next) => {
  if (err && (err.type === 'entity.too.large' || err.type === 'entity.parse.failed')) {
    return res.status(400).json({ error: 'Requisição inválida.' });
  }
  next(err);
});

const DB_PATH = process.env.DB_PATH || './database.db'; // no Render, use um Disk persistente (ex.: /var/data/database.db)
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error("Erro ao abrir banco SQLite:", err.message);
  else console.log("Banco SQLite conectado com sucesso.");
});

// ==========================================
// HELPERS
// ==========================================
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (e, r) => (e ? reject(e) : resolve(r))));
}
function parseLista(str) {
  try { const v = JSON.parse(str); return Array.isArray(v) ? v : []; } catch (e) { return []; }
}

function erroInterno(res, e) {
  console.error('Erro interno:', e && e.message ? e.message : e);
  return res.status(500).json({ error: 'Erro interno. Tente novamente em instantes.' });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (e, r) => (e ? reject(e) : resolve(r))));
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function (e) { return e ? reject(e) : resolve(this); }));
}

// URL pública onde o admin.html está hospedado (ex.: https://seusite.com.br/admin.html)
const ADMIN_URL = String(process.env.ADMIN_URL || '').trim().replace(/[#?].*$/, '');

// Mostra no log (sem revelar valores) quais variáveis de e-mail estão configuradas
const _v = (n) => (String(process.env[n] || '').trim() ? 'OK' : 'FALTANDO');
console.log(`Config de e-mail -> ADMIN_URL: ${_v('ADMIN_URL')} | BREVO_API_KEY: ${_v('BREVO_API_KEY')} | MAIL_FROM: ${_v('MAIL_FROM')}`);

// ---- Limite de tentativas (em memória) ----
const tentativas = new Map();
function limitar(chave, max, janelaMs) {
  const agora = Date.now();
  let r = tentativas.get(chave);
  if (!r || r.expira < agora) { r = { n: 0, expira: agora + janelaMs }; tentativas.set(chave, r); }
  r.n++;
  return r.n <= max;
}
setInterval(() => {
  const agora = Date.now();
  for (const [k, v] of tentativas) if (v.expira < agora) tentativas.delete(k);
}, 10 * 60 * 1000).unref();

// ---- Regras de senha / e-mail / usuário ----
const SENHAS_FRACAS = ['admin123', '12345678', '123456789', '1234567890', 'password', 'senha123', 'admin1234', 'qwerty123', 'printae123'];
const USUARIOS_PROIBIDOS = ['admin', 'administrador', 'root', 'master'];

function validarSenha(senha, usuario) {
  if (typeof senha !== 'string' || senha.length < 8) return 'A senha deve ter pelo menos 8 caracteres.';
  if (senha.length > 72) return 'A senha deve ter no máximo 72 caracteres.';
  if (!/[A-Za-z]/.test(senha) || !/\d/.test(senha)) return 'A senha deve conter letras e números.';
  const baixa = senha.toLowerCase();
  if (SENHAS_FRACAS.some(f => baixa.includes(f))) return 'Essa senha é muito comum. Escolha outra.';
  if (usuario && baixa.includes(String(usuario).toLowerCase())) return 'A senha não pode conter o nome de usuário.';
  return null;
}
function validarEmail(email) {
  return typeof email === 'string' && email.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}
function validarNomeUsuario(u) {
  if (!/^[A-Za-z0-9._-]{3,40}$/.test(u)) return 'O usuário deve ter de 3 a 40 caracteres (letras, números, ponto, hífen ou sublinhado).';
  if (USUARIOS_PROIBIDOS.includes(u.toLowerCase())) return 'Esse nome de usuário é muito previsível. Escolha outro.';
  return null;
}
const esc = (t) => String(t).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const hashToken = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');
const HASH_FALSO = bcrypt.hashSync('senha-falsa-para-igualar-tempo', 10);

// ---- E-mail via API HTTP (Brevo). SMTP é bloqueado no plano gratuito do Render. ----
async function enviarEmail(para, assunto, html) {
  const key = process.env.BREVO_API_KEY;
  const remetente = process.env.MAIL_FROM;
  if (!key || !remetente) {
    console.error('E-mail NÃO enviado: defina BREVO_API_KEY e MAIL_FROM nas variáveis de ambiente do Render.');
    return false;
  }
  try {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': key, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        sender: { name: process.env.MAIL_FROM_NAME || 'Printae.gyn', email: remetente },
        to: [{ email: para }],
        subject: assunto,
        htmlContent: html
      })
    });
    if (!r.ok) { console.error('Falha ao enviar e-mail:', r.status, await r.text()); return false; }
    return true;
  } catch (e) {
    console.error('Erro ao enviar e-mail:', e.message);
    return false;
  }
}

// ==========================================
// CRIAÇÃO E MIGRAÇÃO DAS TABELAS
// ==========================================
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS configuracoes (chave TEXT PRIMARY KEY, valor TEXT)`);

  db.run(`CREATE TABLE IF NOT EXISTS banners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    imagem TEXT NOT NULL,
    link TEXT,
    ordem INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS categorias (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT UNIQUE NOT NULL,
    imagem TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS produtos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    preco REAL NOT NULL,
    categoria TEXT NOT NULL,
    descricao TEXT,
    imagem TEXT,
    imagens TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS cargos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT UNIQUE NOT NULL,
    permissoes TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE NOT NULL,
    senha TEXT NOT NULL,
    is_master INTEGER DEFAULT 0,
    cargo_id INTEGER,
    permissoes_individuais TEXT,
    FOREIGN KEY(cargo_id) REFERENCES cargos(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS clientes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    senha TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS pedidos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cliente_email TEXT NOT NULL,
    itens TEXT NOT NULL,
    subtotal REAL NOT NULL,
    frete REAL NOT NULL,
    total REAL NOT NULL,
    data TEXT NOT NULL
  )`);

  // Clientes: usuário, e-mail verificado e códigos de confirmação / recuperação
  db.run(`ALTER TABLE clientes ADD COLUMN usuario TEXT`, () => {});
  db.run(`ALTER TABLE clientes ADD COLUMN email_verificado INTEGER DEFAULT 0`, () => {});
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_clientes_usuario ON clientes(usuario COLLATE NOCASE)`);
  db.run(`CREATE TABLE IF NOT EXISTS clientes_codigos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cliente_id INTEGER NOT NULL,
    tipo TEXT NOT NULL,
    codigo_hash TEXT NOT NULL,
    expira_em INTEGER NOT NULL,
    tentativas INTEGER DEFAULT 0
  )`);
  // Senhas antigas de clientes (texto puro) passam a ser guardadas como hash
  db.all(`SELECT id, senha FROM clientes`, [], async (err, rows) => {
    if (err) return console.error('Erro na migração de senhas de clientes:', err.message);
    try {
      for (const c of rows) {
        if (!String(c.senha).startsWith('$2')) {
          await dbRun(`UPDATE clientes SET senha = ? WHERE id = ?`, [await bcrypt.hash(String(c.senha), 10), c.id]);
        }
      }
    } catch (e) { console.error('Erro ao converter senhas de clientes:', e.message); }
  });

  // Coluna de status dos pedidos (erro de "coluna duplicada" é ignorado de propósito)
  db.run(`ALTER TABLE pedidos ADD COLUMN status TEXT DEFAULT 'aberto'`, () => {});

  // Recuperação de senha: e-mail e obrigação de trocar a senha no primeiro acesso
  db.run(`ALTER TABLE usuarios ADD COLUMN email TEXT`, () => {});
  db.run(`ALTER TABLE usuarios ADD COLUMN must_change_password INTEGER DEFAULT 0`, () => {});
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email)`);
  db.run(`CREATE TABLE IF NOT EXISTS reset_senha (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    expira_em INTEGER NOT NULL
  )`);

  // Roda depois das migrações acima (o serialize garante a ordem)
  db.all(`SELECT id, usuario, senha, is_master FROM usuarios`, [], async (err, rows) => {
    if (err) return console.error('Erro na migração de senhas:', err.message);
    try {
      // 1) Converte senhas antigas (texto puro) para hash bcrypt
      for (const u of rows) {
        if (!String(u.senha).startsWith('$2')) {
          u.senha = await bcrypt.hash(String(u.senha), 10);
          await dbRun(`UPDATE usuarios SET senha = ? WHERE id = ?`, [u.senha, u.id]);
        }
      }

      // 1b) Recuperação de emergência: defina RESET_MASTER_PASSWORD no Render, reinicie, entre com a
      //     senha definida e REMOVA a variável em seguida (senão a senha é redefinida a cada reinicialização).
      const senhaReset = process.env.RESET_MASTER_PASSWORD;
      if (senhaReset) {
        const m = rows.find(u => u.is_master);
        if (m) {
          m.senha = await bcrypt.hash(senhaReset, 10);
          await dbRun(`UPDATE usuarios SET senha = ?, must_change_password = 1 WHERE id = ?`, [m.senha, m.id]);
          console.log(`>>> RESET DO MASTER: entre com o usuário "${m.usuario}" e a senha de RESET_MASTER_PASSWORD. Depois REMOVA essa variável. <<<`);
        }
      }

      // 2) Garante um master seguro
      const senhaEnv = process.env.ADMIN_INITIAL_PASSWORD;
      const master = rows.find(u => u.is_master);
      if (!master) {
        const inicial = senhaEnv || senhaReset || crypto.randomBytes(12).toString('base64url');
        await dbRun(
          `INSERT INTO usuarios (usuario, senha, is_master, must_change_password) VALUES ('admin', ?, 1, 1)`,
          [await bcrypt.hash(inicial, 10)]
        );
        if (!senhaEnv && !senhaReset) console.log(`>>> SENHA INICIAL DO MASTER (usuário "admin"): ${inicial} <<< (troque no primeiro acesso)`);
      } else if (await bcrypt.compare('admin123', master.senha)) {
        // Master ainda com a senha padrão antiga: obriga a troca
        if (senhaEnv) {
          await dbRun(`UPDATE usuarios SET senha = ?, must_change_password = 1 WHERE id = ?`, [await bcrypt.hash(senhaEnv, 10), master.id]);
          console.log('Senha padrão do master substituída por ADMIN_INITIAL_PASSWORD. Troca obrigatória no primeiro acesso.');
        } else {
          await dbRun(`UPDATE usuarios SET must_change_password = 1 WHERE id = ?`, [master.id]);
          console.warn('ATENÇÃO: o master ainda usa a senha padrão! Defina ADMIN_INITIAL_PASSWORD e reinicie, ou acesse o painel agora para trocá-la.');
        }
      }
    } catch (e) {
      console.error('Erro ao preparar usuário master:', e.message);
    }
  });
});

// ==========================================
// AUTENTICAÇÃO E PERMISSÕES
// ==========================================

// Token de ADMIN (os tokens de cliente não têm "usuario", então não passam aqui)
function autenticarAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });

  jwt.verify(token, JWT_SECRET, JWT_OPTS, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido ou expirado.' });
    if (!user || typeof user.usuario !== 'string' || user.email || user.tipo === 'cliente') {
      return res.status(403).json({ error: 'Token não pertence a um administrador.' });
    }
    // Token provisório (primeiro acesso) só serve para concluir o primeiro acesso
    if (user.setup) return res.status(403).json({ error: 'Conclua o primeiro acesso antes de continuar.', code: 'MUST_CHANGE_PASSWORD' });
    req.user = user;
    next();
  });
}

// Aceita SOMENTE o token provisório emitido quando a troca de senha é obrigatória
function autenticarSetup(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Acesso negado.' });
  jwt.verify(token, JWT_SECRET, JWT_OPTS, (err, user) => {
    if (err || !user || !user.setup || typeof user.usuario !== 'string') {
      return res.status(403).json({ error: 'Sessão de primeiro acesso inválida ou expirada. Faça login novamente.' });
    }
    req.user = user;
    next();
  });
}

// Lê SEMPRE do banco: alterar cargo/permissões vale na hora, sem esperar o token expirar
async function carregarPermissoes(userId) {
  const u = await dbGet(
    `SELECT u.id, u.usuario, u.is_master, u.cargo_id, u.permissoes_individuais, c.permissoes AS cargo_permissoes
     FROM usuarios u LEFT JOIN cargos c ON u.cargo_id = c.id WHERE u.id = ?`,
    [userId]
  );
  if (!u) return null;
  const isMaster = !!u.is_master;
  const permissoes = isMaster
    ? ['all']
    : [...new Set([...parseLista(u.cargo_permissoes), ...parseLista(u.permissoes_individuais)])];
  return { id: u.id, usuario: u.usuario, is_master: isMaster, cargo_id: u.cargo_id, permissoes };
}

// exigirPermissao('a','b') => precisa ter pelo menos UMA delas. Master sempre passa.
// exigirPermissao() sem argumentos => só master.
function exigirPermissao(...necessarias) {
  return [autenticarAdmin, async (req, res, next) => {
    try {
      const atual = await carregarPermissoes(req.user.id);
      if (!atual) return res.status(401).json({ error: 'Usuário não existe mais.' });
      req.admin = atual;
      if (atual.is_master || necessarias.some(p => atual.permissoes.includes(p))) return next();
      return res.status(403).json({ error: 'Você não tem permissão para realizar esta ação.' });
    } catch (e) {
      return erroInterno(res, e);
    }
  }];
}

// Impede que alguém (não master) conceda mais do que ele mesmo possui
async function validarConcessao(admin, cargo_id, permissoesIndividuais) {
  if (admin.is_master) return null;
  const minhas = new Set(admin.permissoes);
  const pedidas = Array.isArray(permissoesIndividuais) ? permissoesIndividuais : [];
  if (pedidas.some(p => !minhas.has(p))) return 'Você não pode conceder permissões que você mesmo não possui.';
  if (cargo_id) {
    const cargo = await dbGet(`SELECT permissoes FROM cargos WHERE id = ?`, [cargo_id]);
    if (cargo && parseLista(cargo.permissoes).some(p => !minhas.has(p))) {
      return 'Você não pode atribuir um cargo com permissões que você mesmo não possui.';
    }
  }
  return null;
}

// ==========================================
// LOGIN ADMIN
// ==========================================
app.post('/api/login', async (req, res) => {
  const usuario = String(req.body.usuario || '').trim();
  const senha = String(req.body.senha || '');
  if (!limitar(`login:${req.ip}:${usuario.toLowerCase()}`, 10, 15 * 60 * 1000)) {
    return res.status(429).json({ error: 'Muitas tentativas. Aguarde 15 minutos e tente novamente.' });
  }
  try {
    const row = await dbGet(`SELECT id, usuario, senha, is_master, email, must_change_password FROM usuarios WHERE usuario = ?`, [usuario]);
    // compara sempre (mesmo sem usuário) para não revelar quais usuários existem pelo tempo de resposta
    const ok = await bcrypt.compare(senha, row ? row.senha : HASH_FALSO);
    if (!row || !ok) return res.status(401).json({ error: 'Usuário ou senha incorretos.' });

    // Primeiro acesso: troca de senha pendente OU master ainda sem e-mail de recuperação cadastrado
    if (row.must_change_password || (row.is_master && !row.email)) {
      const setupToken = jwt.sign({ id: row.id, usuario: row.usuario, setup: true }, JWT_SECRET, { expiresIn: '30m' });
      return res.json({ must_change_password: true, setup_token: setupToken, usuario: row.usuario, is_master: !!row.is_master });
    }

    const atual = await carregarPermissoes(row.id);
    const token = jwt.sign(
      { id: atual.id, usuario: atual.usuario, is_master: atual.is_master ? 1 : 0 },
      JWT_SECRET,
      { expiresIn: '12h' }
    );
    res.json({ token, usuario: atual.usuario, is_master: atual.is_master, permissoes: atual.permissoes });
  } catch (e) {
    res.status(500).json({ error: 'Erro interno ao fazer login.' });
  }
});

// Primeiro acesso.
// MASTER: define usuário, e-mail (recuperação de senha) e senha nova.
// Demais usuários: apenas trocam a senha provisória (sem e-mail, sem mudar o usuário).
app.post('/api/conta/primeiro-acesso', autenticarSetup, async (req, res) => {
  try {
    const row = await dbGet(`SELECT id, usuario, is_master, email, must_change_password FROM usuarios WHERE id = ?`, [req.user.id]);
    const pendente = row && (row.must_change_password || (row.is_master && !row.email));
    if (!pendente) return res.status(400).json({ error: 'Este usuário não precisa de primeiro acesso.' });

    const senhaNova = req.body.senha_nova;
    let novoUsuario = row.usuario;
    let email = row.email || null;

    if (row.is_master) {
      novoUsuario = String(req.body.usuario || row.usuario).trim();
      email = String(req.body.email || '').trim().toLowerCase();
      const eUser = validarNomeUsuario(novoUsuario);
      if (eUser) return res.status(400).json({ error: eUser });
      if (!validarEmail(email)) return res.status(400).json({ error: 'Informe um e-mail válido. Ele será usado para recuperar sua senha.' });

      const dupUser = await dbGet(`SELECT id FROM usuarios WHERE usuario = ? AND id != ?`, [novoUsuario, row.id]);
      if (dupUser) return res.status(409).json({ error: 'Esse nome de usuário já está em uso.' });
      const dupEmail = await dbGet(`SELECT id FROM usuarios WHERE email = ? AND id != ?`, [email, row.id]);
      if (dupEmail) return res.status(409).json({ error: 'Esse e-mail já está em uso.' });
    }

    const eSenha = validarSenha(senhaNova, novoUsuario);
    if (eSenha) return res.status(400).json({ error: eSenha });

    await dbRun(
      `UPDATE usuarios SET usuario = ?, email = ?, senha = ?, must_change_password = 0 WHERE id = ?`,
      [novoUsuario, email, await bcrypt.hash(senhaNova, 10), row.id]
    );
    await dbRun(`DELETE FROM reset_senha WHERE usuario_id = ?`, [row.id]);

    const atual = await carregarPermissoes(row.id);
    const token = jwt.sign(
      { id: atual.id, usuario: atual.usuario, is_master: atual.is_master ? 1 : 0 },
      JWT_SECRET,
      { expiresIn: '12h' }
    );
    res.json({ token, usuario: atual.usuario, is_master: atual.is_master, permissoes: atual.permissoes });
  } catch (e) {
    res.status(500).json({ error: 'Erro interno ao concluir o primeiro acesso.' });
  }
});

// "Esqueci a senha": sempre responde igual, exista ou não o e-mail (não revela cadastros)
app.post('/api/esqueci-senha', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const resposta = { message: 'Se esse e-mail estiver cadastrado, você receberá um link para redefinir a senha em instantes.' };
  res.json(resposta);

  // processamento em segundo plano (também evita diferença de tempo entre e-mail existente e inexistente)
  (async () => {
    try {
      if (!validarEmail(email)) return console.log('esqueci-senha: e-mail com formato inválido.');
      if (!limitar(`esqueci-ip:${req.ip}`, 5, 60 * 60 * 1000) || !limitar(`esqueci-email:${email}`, 3, 60 * 60 * 1000)) {
        return console.log('esqueci-senha: limite de pedidos por hora atingido (aguarde 1h ou reinicie o serviço).');
      }
      if (!ADMIN_URL) return console.error('ADMIN_URL não definida: não é possível montar o link de recuperação.');

      const u = await dbGet(`SELECT id, usuario FROM usuarios WHERE email = ? AND is_master = 1`, [email]); // recuperação por e-mail: somente master
      if (!u) return console.log(`esqueci-senha: nenhum usuário MASTER cadastrado com o e-mail ${email}.`);

      const token = crypto.randomBytes(32).toString('hex');
      await dbRun(`DELETE FROM reset_senha WHERE usuario_id = ?`, [u.id]); // invalida links anteriores
      await dbRun(`INSERT INTO reset_senha (usuario_id, token_hash, expira_em) VALUES (?, ?, ?)`, [u.id, hashToken(token), Date.now() + 30 * 60 * 1000]);

      const link = `${ADMIN_URL}#reset=${token}`;
      const enviado = await enviarEmail(email, 'Redefinição de senha - Painel Printae.gyn', `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#222">
          <h2>Redefinir senha</h2>
          <p>Olá, <b>${esc(u.usuario)}</b>! Recebemos um pedido para redefinir a senha do painel administrativo.</p>
          <p><a href="${link}" style="display:inline-block;background:#6b2fd1;color:#fff;padding:12px 22px;border-radius:10px;text-decoration:none;font-weight:bold">Criar nova senha</a></p>
          <p style="font-size:13px;color:#555">Este link vale por 30 minutos e só pode ser usado uma vez. Se você não pediu isso, ignore este e-mail: sua senha continua a mesma.</p>
        </div>`);
      console.log(enviado ? `esqueci-senha: e-mail enviado para ${email}.` : 'esqueci-senha: FALHA ao enviar o e-mail (veja o erro acima).');
    } catch (e) {
      console.error('Erro no esqueci-senha:', e.message);
    }
  })();
});

// Confirma a redefinição usando o link recebido por e-mail
app.post('/api/redefinir-senha', async (req, res) => {
  if (!limitar(`redefinir:${req.ip}`, 10, 15 * 60 * 1000)) {
    return res.status(429).json({ error: 'Muitas tentativas. Aguarde alguns minutos.' });
  }
  try {
    const { token, senha_nova } = req.body;
    if (!token || typeof token !== 'string') return res.status(400).json({ error: 'Link inválido.' });

    const r = await dbGet(`SELECT usuario_id FROM reset_senha WHERE token_hash = ? AND expira_em > ?`, [hashToken(token), Date.now()]);
    if (!r) return res.status(400).json({ error: 'Link inválido ou expirado. Solicite um novo em "Esqueci minha senha".' });

    const u = await dbGet(`SELECT id, usuario, email FROM usuarios WHERE id = ?`, [r.usuario_id]);
    if (!u) return res.status(400).json({ error: 'Link inválido.' });

    const eSenha = validarSenha(senha_nova, u.usuario);
    if (eSenha) return res.status(400).json({ error: eSenha });

    await dbRun(`UPDATE usuarios SET senha = ?, must_change_password = 0 WHERE id = ?`, [await bcrypt.hash(senha_nova, 10), u.id]);
    await dbRun(`DELETE FROM reset_senha WHERE usuario_id = ?`, [u.id]); // link de uso único

    if (u.email) {
      enviarEmail(u.email, 'Sua senha foi alterada - Painel Printae.gyn',
        `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto"><p>Olá, <b>${esc(u.usuario)}</b>. A senha do painel administrativo acabou de ser alterada. Se não foi você, entre em contato com o administrador imediatamente.</p></div>`);
    }
    res.json({ message: 'Senha redefinida com sucesso! Faça login com a nova senha.' });
  } catch (e) {
    res.status(500).json({ error: 'Erro interno ao redefinir a senha.' });
  }
});

// Quem sou eu + permissões efetivas ATUAIS (o painel usa isto para montar o menu)
app.get('/api/me', autenticarAdmin, async (req, res) => {
  try {
    const atual = await carregarPermissoes(req.user.id);
    if (!atual) return res.status(401).json({ error: 'Usuário não existe mais.' });
    res.json(atual);
  } catch (e) {
    erroInterno(res, e);
  }
});

// ==========================================
// CLIENTES: CADASTRO, CONFIRMAÇÃO DE E-MAIL, LOGIN E RECUPERAÇÃO
// ==========================================
const NOME_LOJA = process.env.MAIL_FROM_NAME || 'Printae.gyn';

function validarUsuarioCliente(u) {
  if (!/^[A-Za-z0-9._-]{3,30}$/.test(u)) return 'O nome de usuário deve ter de 3 a 30 caracteres (letras, números, ponto, hífen ou sublinhado).';
  if (USUARIOS_PROIBIDOS.includes(u.toLowerCase())) return 'Esse nome de usuário não está disponível. Escolha outro.';
  return null;
}
const normEmail = (e) => String(e || '').trim().toLowerCase();

function tokenCliente(c) {
  return jwt.sign({ id: c.id, email: c.email, tipo: 'cliente' }, JWT_SECRET, { expiresIn: '30d' });
}

function autenticarCliente(req, res, next) {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Faça login para continuar.' });
  jwt.verify(token, JWT_SECRET, JWT_OPTS, (err, u) => {
    if (err || !u || u.tipo !== 'cliente') return res.status(401).json({ error: 'Sessão expirada. Faça login novamente.' });
    req.cliente = u;
    next();
  });
}

// Gera um código de 6 dígitos, guarda só o hash e envia por e-mail
async function enviarCodigo(cliente, tipo) {
  const codigo = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  await dbRun(`DELETE FROM clientes_codigos WHERE cliente_id = ? AND tipo = ?`, [cliente.id, tipo]);
  await dbRun(`INSERT INTO clientes_codigos (cliente_id, tipo, codigo_hash, expira_em) VALUES (?, ?, ?, ?)`,
    [cliente.id, tipo, hashToken(`${cliente.id}:${tipo}:${codigo}`), Date.now() + 15 * 60 * 1000]);

  const titulo = tipo === 'verificar' ? 'Confirme seu e-mail' : 'Recuperação de senha';
  const texto = tipo === 'verificar'
    ? 'Use o código abaixo para confirmar seu e-mail e ativar sua conta:'
    : 'Use o código abaixo para criar uma nova senha:';
  return enviarEmail(cliente.email, `${titulo} - ${NOME_LOJA}`, `
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#222">
      <h2>${titulo}</h2>
      <p>Olá${cliente.usuario ? ', <b>' + esc(cliente.usuario) + '</b>' : ''}! ${texto}</p>
      <p style="font-size:34px;letter-spacing:8px;font-weight:bold;background:#f3eefc;padding:14px 18px;border-radius:12px;text-align:center">${codigo}</p>
      <p style="font-size:13px;color:#555">O código vale por 15 minutos. Se não foi você, ignore este e-mail: nada será alterado.</p>
    </div>`);
}

// Confere o código (máx. 5 tentativas, uso único). Retorna true/false.
async function conferirCodigo(clienteId, tipo, codigo) {
  const r = await dbGet(`SELECT id, codigo_hash, expira_em, tentativas FROM clientes_codigos WHERE cliente_id = ? AND tipo = ?`, [clienteId, tipo]);
  if (!r || r.expira_em < Date.now() || r.tentativas >= 5) return false;
  const ok = hashToken(`${clienteId}:${tipo}:${String(codigo || '').trim()}`) === r.codigo_hash;
  if (!ok) { await dbRun(`UPDATE clientes_codigos SET tentativas = tentativas + 1 WHERE id = ?`, [r.id]); return false; }
  await dbRun(`DELETE FROM clientes_codigos WHERE id = ?`, [r.id]);
  return true;
}

// Cadastro: usuário, e-mail + confirmação, senha + confirmação. A conta só fica ativa após o código do e-mail.
app.post('/api/clientes/cadastro', async (req, res) => {
  try {
    if (!limitar(`cad:${req.ip}`, 10, 60 * 60 * 1000)) return res.status(429).json({ error: 'Muitas tentativas. Aguarde um pouco e tente de novo.' });
    const usuario = String(req.body.usuario || '').trim();
    const email = normEmail(req.body.email);
    const emailConf = normEmail(req.body.email_confirmacao);
    const senha = req.body.senha;
    const senhaConf = req.body.senha_confirmacao;

    const eUser = validarUsuarioCliente(usuario);
    if (eUser) return res.status(400).json({ error: eUser });
    if (!validarEmail(email)) return res.status(400).json({ error: 'Informe um e-mail válido.' });
    if (email !== emailConf) return res.status(400).json({ error: 'Os e-mails não conferem.' });
    if (senha !== senhaConf) return res.status(400).json({ error: 'As senhas não conferem.' });
    const eSenha = validarSenha(senha, usuario);
    if (eSenha) return res.status(400).json({ error: eSenha });

    const existente = await dbGet(`SELECT id, email_verificado FROM clientes WHERE email = ?`, [email]);
    if (existente && existente.email_verificado) {
      return res.status(409).json({ error: 'Este e-mail já está cadastrado. Entre na sua conta ou use "Esqueci minha senha".' });
    }
    const outro = await dbGet(`SELECT id FROM clientes WHERE usuario = ? COLLATE NOCASE AND email != ?`, [usuario, email]);
    if (outro) return res.status(409).json({ error: 'Esse nome de usuário já está em uso.' });

    const hash = await bcrypt.hash(senha, 10);
    let id;
    if (existente) { // cadastro anterior nunca confirmado: atualiza e reenvia o código
      await dbRun(`UPDATE clientes SET usuario = ?, senha = ? WHERE id = ?`, [usuario, hash, existente.id]);
      id = existente.id;
    } else {
      const r = await dbRun(`INSERT INTO clientes (email, senha, usuario, email_verificado) VALUES (?, ?, ?, 0)`, [email, hash, usuario]);
      id = r.lastID;
    }
    const enviado = await enviarCodigo({ id, email, usuario }, 'verificar');
    if (!enviado) return res.status(502).json({ error: 'Não foi possível enviar o e-mail de confirmação agora. Tente novamente em alguns minutos.' });
    res.json({ message: 'Enviamos um código de 6 dígitos para o seu e-mail. Digite-o para ativar a conta.' });
  } catch (e) { erroInterno(res, e); }
});

// Confirma o e-mail com o código recebido e já entra na conta
app.post('/api/clientes/verificar-email', async (req, res) => {
  try {
    const email = normEmail(req.body.email);
    if (!limitar(`ver:${req.ip}:${email}`, 10, 15 * 60 * 1000)) return res.status(429).json({ error: 'Muitas tentativas. Aguarde alguns minutos.' });
    const c = await dbGet(`SELECT id, email, usuario FROM clientes WHERE email = ?`, [email]);
    const ok = c && await conferirCodigo(c.id, 'verificar', req.body.codigo);
    if (!ok) return res.status(400).json({ error: 'Código inválido ou expirado. Peça um novo código.' });
    await dbRun(`UPDATE clientes SET email_verificado = 1 WHERE id = ?`, [c.id]);
    res.json({ token: tokenCliente(c), email: c.email, usuario: c.usuario, message: 'E-mail confirmado! Você já está logado.' });
  } catch (e) { erroInterno(res, e); }
});

// Reenvio do código (resposta sempre igual: não revela se o e-mail existe)
app.post('/api/clientes/reenviar-codigo', async (req, res) => {
  res.json({ message: 'Se o e-mail estiver aguardando confirmação, enviamos um novo código.' });
  try {
    const email = normEmail(req.body.email);
    if (!validarEmail(email)) return;
    if (!limitar(`reenv-ip:${req.ip}`, 10, 60 * 60 * 1000) || !limitar(`reenv:${email}`, 4, 60 * 60 * 1000)) return;
    const c = await dbGet(`SELECT id, email, usuario FROM clientes WHERE email = ? AND email_verificado = 0`, [email]);
    if (c) await enviarCodigo(c, 'verificar');
  } catch (e) { console.error('reenviar-codigo:', e.message); }
});

// Login (somente com e-mail confirmado)
app.post('/api/clientes/login', async (req, res) => {
  try {
    const email = normEmail(req.body.email);
    const senha = String(req.body.senha || '');
    if (!email || !senha) return res.status(400).json({ error: 'Informe e-mail e senha.' });
    if (!limitar(`clogin:${req.ip}:${email}`, 10, 15 * 60 * 1000)) return res.status(429).json({ error: 'Muitas tentativas. Aguarde 15 minutos.' });

    const c = await dbGet(`SELECT id, email, usuario, senha, email_verificado FROM clientes WHERE email = ?`, [email]);
    const ok = await bcrypt.compare(senha, c ? c.senha : HASH_FALSO);
    if (!c || !ok) return res.status(401).json({ error: 'E-mail ou senha incorretos.' });

    if (!c.email_verificado) {
      if (limitar(`reenv:${email}`, 4, 60 * 60 * 1000)) await enviarCodigo(c, 'verificar');
      return res.status(403).json({ code: 'EMAIL_NAO_VERIFICADO', error: 'Confirme seu e-mail para entrar. Enviamos um código para você.' });
    }
    res.json({ token: tokenCliente(c), email: c.email, usuario: c.usuario });
  } catch (e) { erroInterno(res, e); }
});

// Recuperação de senha do cliente: passo 1 (pede o código)
app.post('/api/clientes/esqueci-senha', async (req, res) => {
  res.json({ message: 'Se esse e-mail estiver cadastrado, enviamos um código para redefinir a senha.' });
  try {
    const email = normEmail(req.body.email);
    if (!validarEmail(email)) return;
    if (!limitar(`cesq-ip:${req.ip}`, 10, 60 * 60 * 1000) || !limitar(`cesq:${email}`, 3, 60 * 60 * 1000)) return;
    const c = await dbGet(`SELECT id, email, usuario FROM clientes WHERE email = ? AND email_verificado = 1`, [email]);
    if (c) await enviarCodigo(c, 'reset');
  } catch (e) { console.error('esqueci-senha (cliente):', e.message); }
});

// Recuperação de senha do cliente: passo 2 (código + nova senha)
app.post('/api/clientes/redefinir-senha', async (req, res) => {
  try {
    const email = normEmail(req.body.email);
    if (!limitar(`credef:${req.ip}:${email}`, 10, 15 * 60 * 1000)) return res.status(429).json({ error: 'Muitas tentativas. Aguarde alguns minutos.' });
    if (req.body.senha_nova !== req.body.senha_confirmacao) return res.status(400).json({ error: 'As senhas não conferem.' });
    const c = await dbGet(`SELECT id, usuario FROM clientes WHERE email = ? AND email_verificado = 1`, [email]);
    const eSenha = validarSenha(req.body.senha_nova, c && c.usuario);
    if (eSenha) return res.status(400).json({ error: eSenha });
    const ok = c && await conferirCodigo(c.id, 'reset', req.body.codigo);
    if (!ok) return res.status(400).json({ error: 'Código inválido ou expirado. Peça um novo código.' });
    await dbRun(`UPDATE clientes SET senha = ? WHERE id = ?`, [await bcrypt.hash(req.body.senha_nova, 10), c.id]);
    res.json({ message: 'Senha alterada! Entre com a nova senha.' });
  } catch (e) { erroInterno(res, e); }
});

// ==========================================
// PEDIDOS DO CLIENTE (exigem login; o servidor recalcula os preços)
// ==========================================
app.post('/api/pedidos', autenticarCliente, async (req, res) => {
  try {
    const itensRecebidos = Array.isArray(req.body.itens) ? req.body.itens : [];
    if (!itensRecebidos.length || itensRecebidos.length > 100) return res.status(400).json({ error: 'Carrinho inválido.' });

    const produtos = await dbAll(`SELECT nome, preco, categoria, imagem FROM produtos`);
    const porNome = new Map(produtos.map(p => [String(p.nome).trim().toLowerCase(), p]));
    const itens = [];
    for (const i of itensRecebidos) {
      const p = porNome.get(String(i && i.name || '').trim().toLowerCase());
      const qtd = Math.floor(Number(i && i.quantity));
      if (!p || !(qtd >= 1 && qtd <= 999)) return res.status(400).json({ error: 'Um dos produtos do carrinho não está mais disponível.' });
      itens.push({ name: p.nome, price: Number(p.preco), category: p.categoria, image: p.imagem, quantity: qtd });
    }
    const subtotal = Math.round(itens.reduce((t, i) => t + i.price * i.quantity, 0) * 100) / 100;
    const frete = subtotal >= 199 ? 0 : 15.90;
    const total = Math.round((subtotal + frete) * 100) / 100;

    const r = await dbRun(
      `INSERT INTO pedidos (cliente_email, itens, subtotal, frete, total, data, status) VALUES (?, ?, ?, ?, ?, ?, 'aberto')`,
      [req.cliente.email, JSON.stringify(itens), subtotal, frete, total, new Date().toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' })]
    );
    res.json({ id: r.lastID, subtotal, frete, total, message: 'Pedido registrado com sucesso!' });
  } catch (e) { erroInterno(res, e); }
});

// Só o próprio cliente vê os próprios pedidos
app.get('/api/pedidos/meus', autenticarCliente, (req, res) => {
  db.all(`SELECT id, itens, subtotal, frete, total, data, status FROM pedidos WHERE cliente_email = ? ORDER BY id DESC`, [req.cliente.email], (err, rows) => {
    if (err) return erroInterno(res, err);
    res.json(rows.map(p => ({ ...p, status: p.status || 'aberto', itens: parseLista(p.itens) })));
  });
});

// ==========================================
// PEDIDOS (ADMIN)
// ==========================================
app.get('/api/admin/pedidos', ...exigirPermissao('ver_pedidos', 'finalizar_pedidos', 'cancelar_pedidos'), (req, res) => {
  db.all(`SELECT * FROM pedidos ORDER BY id DESC`, [], (err, rows) => {
    if (err) return erroInterno(res, err);
    res.json(rows.map(p => ({ ...p, status: p.status || 'aberto', itens: parseLista(p.itens) })));
  });
});

app.put('/api/admin/pedidos/:id/status', autenticarAdmin, async (req, res) => {
  const { status } = req.body;
  const exigida = status === 'finalizado' ? 'finalizar_pedidos' : status === 'cancelado' ? 'cancelar_pedidos' : null;
  if (!exigida) return res.status(400).json({ error: 'Status inválido.' });
  try {
    const atual = await carregarPermissoes(req.user.id);
    if (!atual || !(atual.is_master || atual.permissoes.includes(exigida))) {
      return res.status(403).json({ error: 'Você não tem permissão para realizar esta ação.' });
    }
    db.run(`UPDATE pedidos SET status = ? WHERE id = ?`, [status, req.params.id], (err) => {
      if (err) return erroInterno(res, err);
      res.json({ message: 'Status atualizado!' });
    });
  } catch (e) {
    erroInterno(res, e);
  }
});

// ==========================================
// CONFIGURAÇÕES GERAIS
// ==========================================
app.get('/api/configuracoes', (req, res) => {
  db.all(`SELECT * FROM configuracoes`, [], (err, rows) => {
    if (err) return erroInterno(res, err);
    const configObj = {};
    rows.forEach(r => {
      try { configObj[r.chave] = JSON.parse(r.valor); }
      catch (e) { configObj[r.chave] = r.valor; }
    });
    res.json(configObj);
  });
});

// logo_url exige "alterar_logo"; as demais chaves (textos, imagens, contatos) exigem "alterar_textos"
app.post('/api/configuracoes', autenticarAdmin, async (req, res) => {
  const { chave, valor } = req.body;
  if (!chave) return res.status(400).json({ error: 'Chave obrigatória.' });
  const exigida = chave === 'logo_url' ? 'alterar_logo' : 'alterar_textos';
  try {
    const atual = await carregarPermissoes(req.user.id);
    if (!atual || !(atual.is_master || atual.permissoes.includes(exigida))) {
      return res.status(403).json({ error: 'Você não tem permissão para realizar esta ação.' });
    }
    const valorStr = typeof valor === 'object' ? JSON.stringify(valor) : valor;
    db.run(
      `INSERT INTO configuracoes (chave, valor) VALUES (?, ?) ON CONFLICT(chave) DO UPDATE SET valor = ?`,
      [chave, valorStr, valorStr],
      (err) => {
        if (err) return erroInterno(res, err);
        res.json({ message: 'Configuração salva com sucesso!' });
      }
    );
  } catch (e) {
    erroInterno(res, e);
  }
});

// ==========================================
// BANNERS
// ==========================================
app.get('/api/banners', (req, res) => {
  db.all(`SELECT * FROM banners ORDER BY ordem ASC, id DESC`, [], (err, rows) => {
    if (err) return erroInterno(res, err);
    res.json(rows);
  });
});

app.post('/api/banners', ...exigirPermissao('adicionar_banners'), (req, res) => {
  const { imagem, link, ordem } = req.body;
  db.run(`INSERT INTO banners (imagem, link, ordem) VALUES (?, ?, ?)`, [imagem, link || '', ordem || 0], function (err) {
    if (err) return erroInterno(res, err);
    res.json({ id: this.lastID, message: 'Banner adicionado!' });
  });
});

app.delete('/api/banners/:id', ...exigirPermissao('remover_banners'), (req, res) => {
  db.run(`DELETE FROM banners WHERE id = ?`, [req.params.id], (err) => {
    if (err) return erroInterno(res, err);
    res.json({ message: 'Banner removido!' });
  });
});

// ==========================================
// CATEGORIAS
// ==========================================
app.get('/api/categorias', (req, res) => {
  db.all(`SELECT * FROM categorias ORDER BY nome ASC`, [], (err, rows) => {
    if (err) return erroInterno(res, err);
    res.json(rows);
  });
});

app.post('/api/categorias', ...exigirPermissao('adicionar_categorias'), (req, res) => {
  const { nome, imagem } = req.body;
  db.run(`INSERT INTO categorias (nome, imagem) VALUES (?, ?)`, [nome, imagem || ''], function (err) {
    if (err) return erroInterno(res, err);
    res.json({ id: this.lastID, message: 'Categoria cadastrada!' });
  });
});

app.put('/api/categorias/:id', ...exigirPermissao('editar_categorias'), (req, res) => {
  const { nome, imagem } = req.body;
  db.run(`UPDATE categorias SET nome = ?, imagem = ? WHERE id = ?`, [nome, imagem || '', req.params.id], (err) => {
    if (err) return erroInterno(res, err);
    res.json({ message: 'Categoria atualizada!' });
  });
});

app.delete('/api/categorias/:id', ...exigirPermissao('remover_categorias'), (req, res) => {
  db.run(`DELETE FROM categorias WHERE id = ?`, [req.params.id], (err) => {
    if (err) return erroInterno(res, err);
    res.json({ message: 'Categoria removida!' });
  });
});

// ==========================================
// PRODUTOS
// ==========================================
app.get('/api/produtos', (req, res) => {
  db.all(`SELECT * FROM produtos ORDER BY id DESC`, [], (err, rows) => {
    if (err) return erroInterno(res, err);
    res.json(rows);
  });
});

app.post('/api/produtos', ...exigirPermissao('adicionar_produtos'), (req, res) => {
  const { nome, preco, categoria, descricao, imagem, imagens } = req.body;
  const imagensJson = Array.isArray(imagens) ? JSON.stringify(imagens) : JSON.stringify([imagem || '']);
  const imagemPrincipal = imagem || (Array.isArray(imagens) && imagens[0]) || '';

  db.run(
    `INSERT INTO produtos (nome, preco, categoria, descricao, imagem, imagens) VALUES (?, ?, ?, ?, ?, ?)`,
    [nome, preco, categoria, descricao, imagemPrincipal, imagensJson],
    function (err) {
      if (err) return erroInterno(res, err);
      res.json({ id: this.lastID, message: 'Produto cadastrado!' });
    }
  );
});

app.put('/api/produtos/:id', ...exigirPermissao('editar_produtos'), (req, res) => {
  const { nome, preco, categoria, descricao, imagem, imagens } = req.body;
  const imagensJson = Array.isArray(imagens) ? JSON.stringify(imagens) : JSON.stringify([imagem || '']);
  const imagemPrincipal = imagem || (Array.isArray(imagens) && imagens[0]) || '';

  db.run(
    `UPDATE produtos SET nome = ?, preco = ?, categoria = ?, descricao = ?, imagem = ?, imagens = ? WHERE id = ?`,
    [nome, preco, categoria, descricao, imagemPrincipal, imagensJson, req.params.id],
    (err) => {
      if (err) return erroInterno(res, err);
      res.json({ message: 'Produto atualizado!' });
    }
  );
});

app.delete('/api/produtos/:id', ...exigirPermissao('remover_produtos'), (req, res) => {
  db.run(`DELETE FROM produtos WHERE id = ?`, [req.params.id], (err) => {
    if (err) return erroInterno(res, err);
    res.json({ message: 'Produto removido!' });
  });
});

// ==========================================
// CARGOS (somente master cria/edita; quem gerencia usuários pode LISTAR para escolher)
// ==========================================
app.get('/api/cargos', ...exigirPermissao('adicionar_admin', 'editar_admin'), (req, res) => {
  db.all(`SELECT * FROM cargos ORDER BY nome ASC`, [], (err, rows) => {
    if (err) return erroInterno(res, err);
    res.json(rows.map(r => ({ ...r, permissoes: parseLista(r.permissoes) })));
  });
});

app.post('/api/cargos', ...exigirPermissao(), (req, res) => {
  const { nome, permissoes } = req.body;
  db.run(`INSERT INTO cargos (nome, permissoes) VALUES (?, ?)`, [nome, JSON.stringify(permissoes || [])], function (err) {
    if (err) return erroInterno(res, err);
    res.json({ id: this.lastID, message: 'Cargo criado!' });
  });
});

app.put('/api/cargos/:id', ...exigirPermissao(), (req, res) => {
  const { nome, permissoes } = req.body;
  db.run(`UPDATE cargos SET nome = ?, permissoes = ? WHERE id = ?`, [nome, JSON.stringify(permissoes || []), req.params.id], (err) => {
    if (err) return erroInterno(res, err);
    res.json({ message: 'Cargo atualizado com sucesso!' });
  });
});

// ==========================================
// USUÁRIOS ADMIN
// ==========================================
app.get('/api/usuarios', ...exigirPermissao('adicionar_admin', 'editar_admin', 'remover_admin', 'alterar_senha_admin'), (req, res) => {
  db.all(
    `SELECT u.id, u.usuario, u.is_master, u.cargo_id, u.permissoes_individuais, c.nome as cargo_nome
     FROM usuarios u LEFT JOIN cargos c ON u.cargo_id = c.id`,
    [],
    (err, rows) => {
      if (err) return erroInterno(res, err);
      res.json(rows.map(u => ({ ...u, permissoes_individuais: parseLista(u.permissoes_individuais) })));
    }
  );
});

app.post('/api/usuarios', ...exigirPermissao('adicionar_admin'), async (req, res) => {
  const { usuario, senha, cargo_id, permissoes_individuais } = req.body;
  if (!usuario || !senha) return res.status(400).json({ error: 'Usuário e senha são obrigatórios.' });
  try {
    const eUser = validarNomeUsuario(String(usuario).trim());
    if (eUser) return res.status(400).json({ error: eUser });
    const eSenha = validarSenha(senha, usuario);
    if (eSenha) return res.status(400).json({ error: eSenha });
    const negado = await validarConcessao(req.admin, cargo_id, permissoes_individuais);
    if (negado) return res.status(403).json({ error: negado });

    // A senha definida aqui é provisória: o novo usuário será obrigado a trocá-la (e informar e-mail) no primeiro acesso
    db.run(
      `INSERT INTO usuarios (usuario, senha, is_master, cargo_id, permissoes_individuais, must_change_password) VALUES (?, ?, 0, ?, ?, 1)`,
      [usuario, await bcrypt.hash(senha, 10), cargo_id || null, JSON.stringify(permissoes_individuais || [])],
      function (err) {
        if (err) return erroInterno(res, err);
        res.json({ id: this.lastID, message: 'Usuário admin criado!' });
      }
    );
  } catch (e) {
    erroInterno(res, e);
  }
});

// PUT só com { senha } = troca de senha ("alterar_senha_admin").
// PUT com usuario/cargo/permissões = edição ("editar_admin"); senha junto exige as duas.
app.put('/api/usuarios/:id', autenticarAdmin, async (req, res) => {
  const { usuario, senha, cargo_id, permissoes_individuais } = req.body;
  const id = req.params.id;
  const temSenha = typeof senha === 'string' && senha.trim() !== '';
  const editaDados = usuario !== undefined || cargo_id !== undefined || permissoes_individuais !== undefined;

  try {
    const atual = await carregarPermissoes(req.user.id);
    if (!atual) return res.status(401).json({ error: 'Usuário não existe mais.' });
    const pode = (p) => atual.is_master || atual.permissoes.includes(p);

    if (temSenha && !pode('alterar_senha_admin')) {
      return res.status(403).json({ error: 'Você não tem permissão para alterar senhas.' });
    }
    if (editaDados && !pode('editar_admin')) {
      return res.status(403).json({ error: 'Você não tem permissão para editar usuários.' });
    }
    if (!temSenha && !editaDados) return res.status(400).json({ error: 'Nada para atualizar.' });

    if (editaDados) {
      const negado = await validarConcessao(atual, cargo_id, permissoes_individuais);
      if (negado) return res.status(403).json({ error: negado });
    }

    const sets = [];
    const params = [];
    if (editaDados) {
      sets.push('usuario = ?', 'cargo_id = ?', 'permissoes_individuais = ?');
      params.push(usuario, cargo_id || null, JSON.stringify(permissoes_individuais || []));
    }
    if (temSenha) {
      const alvo = await dbGet(`SELECT usuario FROM usuarios WHERE id = ? AND is_master = 0`, [id]);
      if (!alvo) return res.status(404).json({ error: 'Usuário não encontrado.' });
      const eSenha = validarSenha(senha, usuario || alvo.usuario);
      if (eSenha) return res.status(400).json({ error: eSenha });
      // senha definida por outra pessoa é provisória: o usuário precisa trocá-la ao entrar
      sets.push('senha = ?', 'must_change_password = ?');
      params.push(await bcrypt.hash(senha, 10), String(id) === String(atual.id) ? 0 : 1);
      await dbRun(`DELETE FROM reset_senha WHERE usuario_id = ?`, [id]);
    }
    params.push(id);

    db.run(`UPDATE usuarios SET ${sets.join(', ')} WHERE id = ? AND is_master = 0`, params, (err) => {
      if (err) return erroInterno(res, err);
      res.json({ message: 'Usuário atualizado com sucesso!' });
    });
  } catch (e) {
    erroInterno(res, e);
  }
});

app.delete('/api/usuarios/:id', ...exigirPermissao('remover_admin'), (req, res) => {
  if (String(req.params.id) === String(req.admin.id)) {
    return res.status(400).json({ error: 'Você não pode excluir a si mesmo.' });
  }
  db.run(`DELETE FROM usuarios WHERE id = ? AND is_master = 0`, [req.params.id], (err) => {
    if (err) return erroInterno(res, err);
    res.json({ message: 'Usuário removido!' });
  });
});

process.on('unhandledRejection', (e) => console.error('Promessa rejeitada:', e && e.message ? e.message : e));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
