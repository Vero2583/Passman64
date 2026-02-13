import { db } from "../config/db.js";

// création d'un password

export const createPassword = async (data) => {
  try {
    await db.query(
      "INSERT INTO entrees (user_id, service_name, login, password_hash, iv) VALUES (?,?,?,?, ?)",
      [
        data.user_id,
        data.service_name,
        data.login,
        data.password_hash,
        data.iv,
      ],
    );
  } catch (error) {
    console.error(" Erreur createPassword :", error.message);
    throw error;
  }
};

// récupération de tous les passwords
export const getAllPasswords = async (user_id) => {
  try {
    const [rows] = await db.query("SELECT * FROM entrees WHERE user_id = ?", [
      user_id,
    ]);
    return rows;
  } catch (error) {
    console.error(" Erreur getAllPasswords :", error.message);
    throw error;
  }
};

// récupération d'un password par ID

export const getPasswordById = async (id) => {
  try {
    const [rows] = await db.query("SELECT * FROM entrees WHERE id = ?", [id]);
    return rows[0] || null;
  } catch (error) {
    console.error("Erreur getPasswordById :", error.message);
    throw error;
  }
};

export const updatePasswordById = async (id, data) => {
  try {
    await db.query(
      "UPDATE entrees SET user_id = ?, service_name = ?, login = ?, password_hash = ?, iv = ? WHERE id = ?",
      [
        data.user_id,
        data.service_name,
        data.login,
        data.password_hash,
        data.iv,
        id,
      ],
    );
  } catch (error) {
    console.error("Erreur lors de la mise à jour par id", error.message);
    throw error;
  }
};

export const deletePasswordById = async (id) => {
  try {
    const [result] = await db.query("DELETE FROM entrees WHERE id = ?", [id]);

    return result.affectedRows > 0;
  } catch (error) {
    console.error("Erreur lors de la suppression par id:", error.message);
    throw error;
  }
};
