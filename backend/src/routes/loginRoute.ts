import { Router } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import pool from "../database/conexao";

const router = Router();
const refreshTokens: string[] = [];

function generateAccessToken(user: { id: number; nome: string; email: string }) {
    return jwt.sign(
        { id: user.id, nome: user.nome, email: user.email },
        process.env.JWT_SECRET!,
        { expiresIn: "15m" }
    );
}

function generateRefreshToken(user: { id: number }) {
    return jwt.sign(
        { id: user.id },
        process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET!,
        { expiresIn: "7d" }
    );
}

router.post("/", async (req, res) => {
    const { login, senha } = req.body;

    if (!login || !senha) {
        return res.status(400).json({ erro: "Login e senha são obrigatórios" });
    }

    const resultado = await pool.query(
        "SELECT * FROM usuarios WHERE email = $1 OR nome = $1",
        [login]
    );

    const usuario = resultado.rows[0];

    if (!usuario) {
        return res.status(401).json({ erro: "Credenciais inválidas" });
    }

    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    if (!senhaValida) {
        return res.status(401).json({ erro: "Credenciais inválidas" });
    }

    const accessToken = generateAccessToken({
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
    });

    const refreshToken = generateRefreshToken({ id: usuario.id });
    refreshTokens.push(refreshToken);

    return res.json({ accessToken, refreshToken });
});

router.post("/refresh", async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ erro: "Refresh token não fornecido" });
    }

    if (!refreshTokens.includes(refreshToken)) {
        return res.status(403).json({ erro: "Refresh token inválido" });
    }

    try {
        const payload = jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET!
        ) as { id: number };

        const resultado = await pool.query(
            "SELECT id, nome, email FROM usuarios WHERE id = $1",
            [payload.id]
        );

        const usuario = resultado.rows[0];

        if (!usuario) {
            return res.status(404).json({ erro: "Usuário não encontrado" });
        }

        const accessToken = generateAccessToken({
            id: usuario.id,
            nome: usuario.nome,
            email: usuario.email,
        });

        const newRefreshToken = generateRefreshToken({ id: usuario.id });
        const index = refreshTokens.indexOf(refreshToken);
        if (index !== -1) {
            refreshTokens.splice(index, 1, newRefreshToken);
        } else {
            refreshTokens.push(newRefreshToken);
        }

        return res.json({ accessToken, refreshToken: newRefreshToken });
    } catch {
        return res.status(403).json({ erro: "Refresh token inválido" });
    }
});

router.post("/logout", (req, res) => {
    const { refreshToken } = req.body;

    if (refreshToken) {
        const index = refreshTokens.indexOf(refreshToken);
        if (index !== -1) {
            refreshTokens.splice(index, 1);
        }
    }

    return res.sendStatus(204);
});

export default router;
