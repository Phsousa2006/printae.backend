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

// CRIAÇÃO E MIGRAÇÃO DAS TABELAS
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
    FOREIGN KEY(cargo_id) REFERENCES cargos(id)
  )`);

  // Criar Admin Master padrão se não existir
  db.get(`SELECT * FROM usuarios WHERE is_master = 1`, (err, master) => {
    if (!master) {
      db.run(`INSERT INTO usuarios (usuario, senha, is_master) VALUES ('admin', 'admin123', 1)`);
    }
  });
});

// MIDDLEWARE DE AUTENTICAÇÃO
function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido ou expirado.' });
    req.user = user;
    next();
  });
}

// LOGIN
app.post('/api/login', (req, res) => {
  const { usuario, senha } = req.body;
  db.get(
    `SELECT u.*, c.permissoes FROM usuarios u LEFT JOIN cargos c ON u.cargo_id = c.id WHERE u.usuario = ? AND u.senha = ?`,
    [usuario, senha],
    (err, user) => {
      if (err || !user) return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
      
      const permissoesArray = user.is_master ? ['all'] : (user.permissoes ? JSON.parse(user.permissoes) : []);
      const token = jwt.sign({ id: user.id, usuario: user.usuario, is_master: user.is_master, permissoes: permissoesArray }, JWT_SECRET, { expiresIn: '12h' });
      
      res.json({ token, usuario: user.usuario, is_master: !!user.is_master, permissoes: permissoesArray });
    }
  );
});

// CONFIGURAÇÕES GERAIS
app.get('/api/configuracoes', (req, res) => {
  db.all(`SELECT * FROM configuracoes`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const configObj = {};
    rows.forEach(r => {
      try { configObj[r.chave] = JSON.parse(r.valor); }
      catch(e) { configObj[r.chave] = r.valor; }
    });
    res.json(configObj);
  });
});

app.post('/api/configuracoes', autenticarToken, (req, res) => {
  const { chave, valor } = req.body;
  const valorStr = typeof valor === 'object' ? JSON.stringify(valor) : valor;
  db.run(
    `INSERT INTO configuracoes (chave, valor) VALUES (?, ?) ON CONFLICT(chave) DO UPDATE SET valor = ?`,
    [chave, valorStr, valorStr],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Configuração salva com sucesso!' });
    }
  );
});

// BANNERS ROTATIVOS
app.get('/api/banners', (req, res) => {
  db.all(`SELECT * FROM banners ORDER BY ordem ASC, id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/banners', autenticarToken, (req, res) => {
  const { imagem, link, ordem } = req.body;
  db.run(`INSERT INTO banners (imagem, link, ordem) VALUES (?, ?, ?)`, [imagem, link || '', ordem || 0], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, message: 'Banner adicionado!' });
  });
});

app.delete('/api/banners/:id', autenticarToken, (req, res) => {
  db.run(`DELETE FROM banners WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Banner removido!' });
  });
});

// CATEGORIAS
app.get('/api/categorias', (req, res) => {
  db.all(`SELECT * FROM categorias ORDER BY nome ASC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/categorias', autenticarToken, (req, res) => {
  const { nome, imagem } = req.body;
  db.run(`INSERT INTO categorias (nome, imagem) VALUES (?, ?)`, [nome, imagem || ''], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, message: 'Categoria cadastrada!' });
  });
});

app.put('/api/categorias/:id', autenticarToken, (req, res) => {
  const { nome, imagem } = req.body;
  db.run(`UPDATE categorias SET nome = ?, imagem = ? WHERE id = ?`, [nome, imagem || '', req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Categoria atualizada!' });
  });
});

app.delete('/api/categorias/:id', autenticarToken, (req, res) => {
  db.run(`DELETE FROM categorias WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Categoria removida!' });
  });
});

// PRODUTOS
app.get('/api/produtos', (req, res) => {
  db.all(`SELECT * FROM produtos ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/produtos', autenticarToken, (req, res) => {
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

app.put('/api/produtos/:id', autenticarToken, (req, res) => {
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

app.delete('/api/produtos/:id', autenticarToken, (req, res) => {
  db.run(`DELETE FROM produtos WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Produto removido!' });
  });
});

// CARGOS (CRIAR E EDITAR)
app.get('/api/cargos', autenticarToken, (req, res) => {
  db.all(`SELECT * FROM cargos ORDER BY nome ASC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const lista = rows.map(r => ({
      ...r,
      permissoes: typeof r.permissoes === 'string' ? JSON.parse(r.permissoes) : r.permissoes
    }));
    res.json(lista);
  });
});

app.post('/api/cargos', autenticarToken, (req, res) => {
  const { nome, permissoes } = req.body;
  const permissoesStr = JSON.stringify(permissoes || []);
  db.run(`INSERT INTO cargos (nome, permissoes) VALUES (?, ?)`, [nome, permissoesStr], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, message: 'Cargo criado!' });
  });
});

app.put('/api/cargos/:id', autenticarToken, (req, res) => {
  const { nome, permissoes } = req.body;
  const permissoesStr = JSON.stringify(permissoes || []);
  db.run(`UPDATE cargos SET nome = ?, permissoes = ? WHERE id = ?`, [nome, permissoesStr, req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Cargo atualizado com sucesso!' });
  });
});

// USUÁRIOS ADMINS (CRIAR, EDITAR E EXCLUIR)
app.get('/api/usuarios', autenticarToken, (req, res) => {
  db.all(`SELECT u.id, u.usuario, u.is_master, u.cargo_id, c.nome as cargo_nome FROM usuarios u LEFT JOIN cargos c ON u.cargo_id = c.id`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/usuarios', autenticarToken, (req, res) => {
  const { usuario, senha, cargo_id } = req.body;
  db.run(`INSERT INTO usuarios (usuario, senha, is_master, cargo_id) VALUES (?, ?, 0, ?)`, [usuario, senha, cargo_id || null], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, message: 'Usuário admin criado!' });
  });
});

app.put('/api/usuarios/:id', autenticarToken, (req, res) => {
  const { usuario, senha, cargo_id } = req.body;
  const id = req.params.id;

  if (senha && senha.trim() !== '') {
    // Se digitou uma nova senha, atualiza o nome, senha e o cargo
    db.run(
      `UPDATE usuarios SET usuario = ?, senha = ?, cargo_id = ? WHERE id = ? AND is_master = 0`,
      [usuario, senha, cargo_id || null, id],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Usuário e senha atualizados com sucesso!' });
      }
    );
  } else {
    // Se deixou a senha em branco, atualiza apenas usuário e cargo mantendo a mesma senha
    db.run(
      `UPDATE usuarios SET usuario = ?, cargo_id = ? WHERE id = ? AND is_master = 0`,
      [usuario, cargo_id || null, id],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Usuário e cargo atualizados com sucesso!' });
      }
    );
  }
});

app.delete('/api/usuarios/:id', autenticarToken, (req, res) => {
  db.run(`DELETE FROM usuarios WHERE id = ? AND is_master = 0`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Usuário removido!' });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
