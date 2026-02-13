import jwt from "jsonwebtoken";
import "dotenv/config";

// middleware pour vérifier si on est authentifié

export const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) return res.status(401).json({ message: " Token manquant " });

  const token = authHeader.split(" ")[1];
  
  if (!token) return res.status(401).json({ message: "Token malformé" });
  

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (error) {
    return res.status(403).json({ message: "Token invalide" });
  }
};
