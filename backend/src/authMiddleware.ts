import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

interface JwtPayload {
    id: number;
    nome: string;
    email: string;
    iat?: number;
    exp?: number;
}

export function authMiddleware(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ erro: "Token não fornecido" });
    }

    const [, token] = authHeader.split(" ");

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
        (req as any).user = payload;
        next();
    } catch {
        return res.status(401).json({ erro: "Token inválido" });
    }
}