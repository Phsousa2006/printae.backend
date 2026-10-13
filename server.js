const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'chave-secreta-padrao-local';

// Aumenta o limite de payload para permitir o upload de imagens em Base64
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.use(cors());

// Conexão e Inicialização do Banco de Dados SQLite
const db = new sqlite3.Database('./printae.db', (err) => {
    if (err) console.error("Erro ao conectar ao SQLite:", err.message);
    else console.log("Conectado ao banco SQLite com sucesso.");
});

db.serialize(() => {
    // Tabela de Usuários
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT,
        email TEXT UNIQUE,
        senha TEXT,
        nivel TEXT DEFAULT 'admin'
    )`);

    // Tabela de Produtos
    db.run(`CREATE TABLE IF NOT EXISTS produtos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT,
        preco REAL,
        categoria TEXT,
        descricao TEXT,
        imagem TEXT
    )`);

    // Tabela de Categorias (com imagem)
    db.run(`CREATE TABLE IF NOT EXISTS categorias (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT UNIQUE,
        imagem TEXT
    )`);

    // Criar Admin Padrão se não existir
    db.get(`SELECT * FROM usuarios WHERE email = ?`, ['admin@printaegyn.com.br'], (err, user) => {
        if (!user) {
            const hash = bcrypt.hashSync('admin123', 10);
            db.run(`INSERT INTO usuarios (nome, email, senha, nivel) VALUES (?, ?, ?, ?)`,
                ['Administrador', 'admin@printaegyn.com.br', hash, 'admin']);
        }
    });
});

// Middleware de Autenticação JWT
function autenticarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido ou expirado.' });
        req.user = user;
        next();
    });
}

// --- ROTAS DE AUTENTICAÇÃO ---
app.post('/api/login', (req, res) => {
    const { email, senha } = req.body;
    db.get(`SELECT * FROM usuarios WHERE email = ?`, [email], (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'E-mail ou senha incorretos.' });
        if (!bcrypt.compareSync(senha, user.senha)) return res.status(400).json({ error: 'E-mail ou senha incorretos.' });

        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '8h' });
        res.json({ message: 'Login realizado com sucesso', token, usuario: { nome: user.nome, email: user.email } });
    });
});

// --- ROTAS DE GESTÃO DE USUÁRIOS ---
app.get('/api/usuarios', autenticarToken, (req, res) => {
    db.all(`SELECT id, nome, email, nivel FROM usuarios`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/usuarios', autenticarToken, (req, res) => {
    const { nome, email, senha } = req.body;
    const hash = bcrypt.hashSync(senha, 10);
    db.run(`INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)`, [nome, email, hash], function(err) {
        if (err) return res.status(400).json({ error: 'E-mail já cadastrado.' });
        res.json({ id: this.lastID, nome, email });
    });
});

app.delete('/api/usuarios/:id', autenticarToken, (req, res) => {
    db.run(`DELETE FROM usuarios WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Usuário removido com sucesso.' });
    });
});

// --- ROTAS DE PRODUTOS ---
app.get('/api/produtos', (req, res) => {
    db.all(`SELECT * FROM produtos`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/produtos', autenticarToken, (req, res) => {
    const { nome, preco, categoria, descricao, imagem } = req.body;
    db.run(`INSERT INTO produtos (nome, preco, categoria, descricao, imagem) VALUES (?, ?, ?, ?, ?)`,
        [nome, preco, categoria, descricao, imagem], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID, nome, preco, categoria, descricao, imagem });
        });
});

app.put('/api/produtos/:id', autenticarToken, (req, res) => {
    const { nome, preco, categoria, descricao, imagem } = req.body;
    db.run(`UPDATE produtos SET nome = ?, preco = ?, categoria = ?, descricao = ?, imagem = COALESCE(?, imagem) WHERE id = ?`,
        [nome, preco, categoria, descricao, imagem, req.params.id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Produto atualizado com sucesso.' });
        });
});

app.delete('/api/produtos/:id', autenticarToken, (req, res) => {
    db.run(`DELETE FROM produtos WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Produto excluído com sucesso.' });
    });
});

// --- ROTAS DE CATEGORIAS ---
app.get('/api/categorias', (req, res) => {
    db.all(`SELECT * FROM categorias`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/categorias', autenticarToken, (req, res) => {
    const { nome, imagem } = req.body;
    db.run(`INSERT INTO categorias (nome, imagem) VALUES (?, ?) ON CONFLICT(nome) DO UPDATE SET imagem = ?`,
        [nome, imagem, imagem], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Categoria atualizada com sucesso.' });
        });
});
app.get('/api/recriar-admin', (req, res) => {
    const hash = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR REPLACE INTO usuarios (id, nome, email, senha, nivel) VALUES (1, 'Administrador', 'admin@printaegyn.com.br', ?, 'admin')`, [hash], (err) => {
        if (err) res.send("Erro: " + err.message);
        else res.send("Usuário admin recriado com sucesso! Senha: admin123");
    });
});
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
