const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors()); // Permite que a sua loja e o painel admin acessem a API

const SECRET_KEY = process.env.SECRET_KEY || "chave-secreta-padrao-local";

// Configuração da porta para a nuvem (Render usa process.env.PORT ou 3000 localmente)
const PORT = process.env.PORT || 3000;

// 1. Configurar Banco de Dados SQLite
const db = new sqlite3.Database('./printae.db', (err) => {
  if (err) console.error("Erro ao abrir o banco de dados", err.message);
  else console.log("Conectado ao banco de dados SQLite com sucesso!");
});

// Criar tabelas e o usuário Admin padrão (se não existirem)
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    senha TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS produtos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT,
    preco REAL,
    categoria TEXT,
    imagem TEXT
  )`, () => {
    // Inserir um admin padrão se a tabela estiver vazia
    db.get("SELECT COUNT(*) as count FROM usuarios", async (err, row) => {
      if (row.count === 0) {
        const hashedPassword = await bcrypt.hash("admin123", 10);
        db.run("INSERT INTO usuarios (email, senha) VALUES (?, ?)", ["admin@printaegyn.com.br", hashedPassword]);
        console.log("Usuário Administrador padrão criado: admin@printaegyn.com.br / admin123");
      }
    });
  });
});

// --- ROTAS DA API ---

// 2. Rota de Login do Admin
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM usuarios WHERE email = ?", [email], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: "E-mail ou senha inválidos." });

    const isValidPassword = await bcrypt.compare(password, user.senha);
    if (!isValidPassword) return res.status(401).json({ error: "E-mail ou senha inválidos." });

    // Gera o token JWT com validade de 2 horas
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '2h' });
    res.json({ token });
  });
});

// 3. Rota Pública: Listar Produtos
app.get('/api/produtos', (req, res) => {
  db.all("SELECT * FROM produtos", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Middleware de Segurança para proteger rotas do Admin
function verificarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(403).json({ error: "Token não fornecido." });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Token inválido ou expirado." });
    req.user = decoded;
    next();
  });
}

// 4. Rota Protegida: Adicionar Produto
app.post('/api/produtos', verificarToken, (req, res) => {
  const { nome, preco, categoria, imagem } = req.body;
  
  const query = `INSERT INTO produtos (nome, preco, categoria, imagem) VALUES (?, ?, ?, ?)`;
  db.run(query, [nome, preco, categoria, imagem], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, nome, preco, categoria, imagem });
  });
});

// 5. Rota Protegida: Deletar Produto
app.delete('/api/produtos/:id', verificarToken, (req, res) => {
  const { id } = req.params;
  
  db.run("DELETE FROM produtos WHERE id = ?", [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "Produto excluído com sucesso", changes: this.changes });
  });
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});