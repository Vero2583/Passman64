import express from "express";
import {
  login,
  logout,
  register,
  resetPassword,
  resetPasswordRequest,
  verifyEmail,
} from "../controllers/auth.controller.js";
import { authMiddleware } from "../middlewares/auth.middleware.js";
import {
  validateLogin,
  validateRegister,
  validateResetPasswordRequest,
} from "../middlewares/validation.middleware.js";

const router = express.Router();

router.post("/register", validateRegister, register);
router.post("/login", validateLogin, login);
router.get("/verify", verifyEmail);
router.post(
  "/reset-password-request",
  validateResetPasswordRequest,
  resetPasswordRequest,
);
router.post("/reset-password", resetPassword);
router.post("/logout", authMiddleware, logout);

export default router;
