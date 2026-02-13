import { z } from "zod";

export const validateRegister = (req, res, next) => {
  const schema = z.object({
    email: z.email(),
    password: z.string().min(6),
    confirmPassword: z.string().min(6),
  });
  try {
    schema.parse(req.body);
    if (req.body.password !== req.body.confirmPassword) {
      return res
        .status(400)
        .json({ message: `Les mots de passes ne correspondent pas ` });
    }

    next();
  } catch (error) {
    return res
      .status(400)
      .json({ message: error.issues.map((err) => err.message).join(", ") });
  }
};

export const validateLogin = (req, res, next) => {
  const schema = z.object({
    email: z.email(),
    password: z.string().min(6),
  });

  try {
    schema.parse(req.body);

    next();
  } catch (error) {
    return res
      .status(400)
      .json({ message: error.issues.map((err) => err.message).join(", ") });
  }
};

export const validateResetPasswordRequest = (req, res, next) => {
  const schema = z.object({
    email: z.email("L’adresse email n’est pas valide"),
  });

  try {
    schema.parse(req.body);

    next();
  } catch (error) {
    return res
      .status(400)
      .json({ message: error.issues.map((err) => err.message).join(", ") });
  }
};

//  validation passwords dans la vault

export const validatePassword = (req, res, next) => {
  const schema = z.object({
    service_name: z.string().min(3).optional(),
    login: z.string().optional(),
    password: z.string().optional(),
  });

  try {
    schema.parse(req.body);
    next();
  } catch (error) {
    return res
      .status(400)
      .json({ message: error.issues.map((err) => err.message).join(", ") });
  }
};
