import { Router } from "express";
import bcrypt from "bcryptjs";
import pool from "../database/conexao";

const router = Router();

router.get("/", async (req, res) => {
    const resultado = await pool.query("SELECT * FROM usuarios");
    res.json(resultado.rows);
});

router.post("/", async (req, res) => {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
        return res.status(400).json({ erro: "Nome, email e senha são obrigatórios" });
    }

    const senhaCriptografada = await bcrypt.hash(senha, 10);

    const resultado = await pool.query(
        "INSERT INTO usuarios (nome, email, senha) VALUES ($1, $2, $3) RETURNING *",
        [nome, email, senhaCriptografada]
    );

    res.json(resultado.rows[0]);
});

export default router;