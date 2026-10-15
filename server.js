const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'printae_secret_key_2026';

app.use(cors());
app.use(express.json({ limit: '50mb' }));

const db = new sqlite3.Database('./database.db', (err) => {
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

  // Coluna de status dos pedidos (erro de "coluna duplicada" é ignorado de propósito)
  db.run(`ALTER TABLE pedidos ADD COLUMN status TEXT DEFAULT 'aberto'`, () => {});

  db.get(`SELECT * FROM usuarios WHERE is_master = 1`, (err, master) => {
    if (!master) {
      db.run(`INSERT INTO usuarios (usuario, senha, is_master) VALUES ('admin', 'admin123', 1)`);
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

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido ou expirado.' });
    if (!user || typeof user.usuario !== 'string' || user.email) {
      return res.status(403).json({ error: 'Token não pertence a um administrador.' });
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
      return res.status(500).json({ error: e.message });
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
app.post('/api/login', (req, res) => {
  const { usuario, senha } = req.body;
  db.get(`SELECT id FROM usuarios WHERE usuario = ? AND senha = ?`, [usuario, senha], async (err, row) => {
    if (err || !row) return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
    try {
      const atual = await carregarPermissoes(row.id);
      const token = jwt.sign(
        { id: atual.id, usuario: atual.usuario, is_master: atual.is_master ? 1 : 0 },
        JWT_SECRET,
        { expiresIn: '12h' }
      );
      res.json({ token, usuario: atual.usuario, is_master: atual.is_master, permissoes: atual.permissoes });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
});

// Quem sou eu + permissões efetivas ATUAIS (o painel usa isto para montar o menu)
app.get('/api/me', autenticarAdmin, async (req, res) => {
  try {
    const atual = await carregarPermissoes(req.user.id);
    if (!atual) return res.status(401).json({ error: 'Usuário não existe mais.' });
    res.json(atual);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==========================================
// ROTAS DE CLIENTES (CADASTRO / LOGIN)
// ==========================================
app.post('/api/clientes/auth', (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ error: 'E-mail e senha obrigatórios.' });

  db.get(`SELECT * FROM clientes WHERE email = ?`, [email], (err, cliente) => {
    if (err) return res.status(500).json({ error: err.message });

    if (!cliente) {
      db.run(`INSERT INTO clientes (email, senha) VALUES (?, ?)`, [email, senha], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, email, message: 'Conta criada e login efetuado com sucesso!' });
      });
    } else {
      if (cliente.senha !== senha) {
        return res.status(401).json({ error: 'Senha incorreta.' });
      }
      const token = jwt.sign({ id: cliente.id, email: cliente.email }, JWT_SECRET, { expiresIn: '30d' });
      res.json({ token, email: cliente.email, message: 'Login efetuado com sucesso!' });
    }
  });
});

// ==========================================
// PEDIDOS DO CLIENTE
// ==========================================
app.post('/api/pedidos', (req, res) => {
  const { cliente_email, itens, subtotal, frete, total, data } = req.body;
  if (!cliente_email || !itens) return res.status(400).json({ error: 'Dados do pedido incompletos.' });

  const itensStr = JSON.stringify(itens);
  db.run(
    `INSERT INTO pedidos (cliente_email, itens, subtotal, frete, total, data, status) VALUES (?, ?, ?, ?, ?, ?, 'aberto')`,
    [cliente_email, itensStr, subtotal, frete, total, data || new Date().toLocaleDateString('pt-BR')],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, message: 'Pedido registrado com sucesso!' });
    }
  );
});

app.get('/api/pedidos/:email', (req, res) => {
  db.all(`SELECT * FROM pedidos WHERE cliente_email = ? ORDER BY id DESC`, [req.params.email], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows.map(p => ({ ...p, itens: parseLista(p.itens) })));
  });
});

// ==========================================
// PEDIDOS (ADMIN)
// ==========================================
app.get('/api/admin/pedidos', ...exigirPermissao('ver_pedidos', 'finalizar_pedidos', 'cancelar_pedidos'), (req, res) => {
  db.all(`SELECT * FROM pedidos ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
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
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Status atualizado!' });
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==========================================
// CONFIGURAÇÕES GERAIS
// ==========================================
app.get('/api/configuracoes', (req, res) => {
  db.all(`SELECT * FROM configuracoes`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
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
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Configuração salva com sucesso!' });
      }
    );
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==========================================
// BANNERS
// ==========================================
app.get('/api/banners', (req, res) => {
  db.all(`SELECT * FROM banners ORDER BY ordem ASC, id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/banners', ...exigirPermissao('adicionar_banners'), (req, res) => {
  const { imagem, link, ordem } = req.body;
  db.run(`INSERT INTO banners (imagem, link, ordem) VALUES (?, ?, ?)`, [imagem, link || '', ordem || 0], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, message: 'Banner adicionado!' });
  });
});

app.delete('/api/banners/:id', ...exigirPermissao('remover_banners'), (req, res) => {
  db.run(`DELETE FROM banners WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Banner removido!' });
  });
});

// ==========================================
// CATEGORIAS
// ==========================================
app.get('/api/categorias', (req, res) => {
  db.all(`SELECT * FROM categorias ORDER BY nome ASC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/categorias', ...exigirPermissao('adicionar_categorias'), (req, res) => {
  const { nome, imagem } = req.body;
  db.run(`INSERT INTO categorias (nome, imagem) VALUES (?, ?)`, [nome, imagem || ''], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, message: 'Categoria cadastrada!' });
  });
});

app.put('/api/categorias/:id', ...exigirPermissao('editar_categorias'), (req, res) => {
  const { nome, imagem } = req.body;
  db.run(`UPDATE categorias SET nome = ?, imagem = ? WHERE id = ?`, [nome, imagem || '', req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Categoria atualizada!' });
  });
});

app.delete('/api/categorias/:id', ...exigirPermissao('remover_categorias'), (req, res) => {
  db.run(`DELETE FROM categorias WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Categoria removida!' });
  });
});

// ==========================================
// PRODUTOS
// ==========================================
app.get('/api/produtos', (req, res) => {
  db.all(`SELECT * FROM produtos ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
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
      if (err) return res.status(500).json({ error: err.message });
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
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Produto atualizado!' });
    }
  );
});

app.delete('/api/produtos/:id', ...exigirPermissao('remover_produtos'), (req, res) => {
  db.run(`DELETE FROM produtos WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Produto removido!' });
  });
});

// ==========================================
// CARGOS (somente master cria/edita; quem gerencia usuários pode LISTAR para escolher)
// ==========================================
app.get('/api/cargos', ...exigirPermissao('adicionar_admin', 'editar_admin'), (req, res) => {
  db.all(`SELECT * FROM cargos ORDER BY nome ASC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows.map(r => ({ ...r, permissoes: parseLista(r.permissoes) })));
  });
});

app.post('/api/cargos', ...exigirPermissao(), (req, res) => {
  const { nome, permissoes } = req.body;
  db.run(`INSERT INTO cargos (nome, permissoes) VALUES (?, ?)`, [nome, JSON.stringify(permissoes || [])], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, message: 'Cargo criado!' });
  });
});

app.put('/api/cargos/:id', ...exigirPermissao(), (req, res) => {
  const { nome, permissoes } = req.body;
  db.run(`UPDATE cargos SET nome = ?, permissoes = ? WHERE id = ?`, [nome, JSON.stringify(permissoes || []), req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
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
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows.map(u => ({ ...u, permissoes_individuais: parseLista(u.permissoes_individuais) })));
    }
  );
});

app.post('/api/usuarios', ...exigirPermissao('adicionar_admin'), async (req, res) => {
  const { usuario, senha, cargo_id, permissoes_individuais } = req.body;
  if (!usuario || !senha) return res.status(400).json({ error: 'Usuário e senha são obrigatórios.' });
  try {
    const negado = await validarConcessao(req.admin, cargo_id, permissoes_individuais);
    if (negado) return res.status(403).json({ error: negado });

    db.run(
      `INSERT INTO usuarios (usuario, senha, is_master, cargo_id, permissoes_individuais) VALUES (?, ?, 0, ?, ?)`,
      [usuario, senha, cargo_id || null, JSON.stringify(permissoes_individuais || [])],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, message: 'Usuário admin criado!' });
      }
    );
  } catch (e) {
    res.status(500).json({ error: e.message });
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
    if (temSenha) { sets.push('senha = ?'); params.push(senha); }
    params.push(id);

    db.run(`UPDATE usuarios SET ${sets.join(', ')} WHERE id = ? AND is_master = 0`, params, (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Usuário atualizado com sucesso!' });
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/usuarios/:id', ...exigirPermissao('remover_admin'), (req, res) => {
  if (String(req.params.id) === String(req.admin.id)) {
    return res.status(400).json({ error: 'Você não pode excluir a si mesmo.' });
  }
  db.run(`DELETE FROM usuarios WHERE id = ? AND is_master = 0`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Usuário removido!' });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
