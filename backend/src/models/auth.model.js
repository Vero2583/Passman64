import { db } from "../config/db.js";

// create user

export const createUser = async (email, passwordHash, verifyToken) => {

    const [result] = await db.query(
      "INSERT INTO users (email, password_hash, verify_token) VALUES (?, ?, ?)",
      [email, passwordHash, verifyToken],
    );

    return result.insertId

};

// login trouver un user dans la base de données par son email

export const findUserByEmail = async (email) => {
  const [rows] = await db.query(`SELECT * FROM users WHERE email = ?`, [email]);
  return rows[0]   
};

export const findUserByVerifyToken = async (token) => {
    const [rows] = await db.query(`SELECT * FROM users WHERE verify_token=?`, [token])
    return rows[0]
}

export const verifyUser = async (userId) => {
await db.query(`UPDATE users SET is_verified=1, verify_token=NULL WHERE id=?`, [userId])
}

export const findUserByResetToken=  async (token) => {
  const [rows] =await db.query(`SELECT * FROM users WHERE reset_token=?`, [token])
  return rows[0]
}

export const updatePassword = async (userId, passwordHash) => {
  await db.query(`UPDATE users SET password_hash=? WHERE id =?`, [passwordHash, userId])
}

export const saveResetPassword = async (userId, token) => {
  await db.query(`UPDATE users SET reset_token=? WHERE id=?`, [token, userId])
}
