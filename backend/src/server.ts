import express from "express";
import userRoutes from "./routes/userRoutes";
import loginRoutes from "./routes/loginRoute";
import cors from "cors";

const app = express();

app.use(cors());
app.use(express.json());

app.use("/login", loginRoutes);
app.use("/usuarios", userRoutes);

app.listen(3000, () => {
    console.log("Servidor rodando na porta 3000");
});

