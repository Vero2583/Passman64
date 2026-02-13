import "dotenv/config";
import * as model from "../models/password.model.js";
import {
  decryptPassword,
  encryptPassword,
  getUserKey,
} from "../utils/encryption.util.js";

// création du password

export const create = async (req, res) => {
  try {
    const { service_name, login, password_hash } = req.body;
    const user_id = req.user.id;

    console.log("req.body", req.body);
    console.log("pass_hash", password_hash);

    if (!service_name || !login || !password_hash) {
      return res.status(400).json({
        message: "service_name, login et password_hash sont requis",
      });
    }

    // Récupérer la clé maître en mémoire
    const masterKey = getUserKey(user_id);

    if (!masterKey) {
      return res.status(401).json({
        message: "Session crypto expirée, veuillez vous reconnecter",
      });
    }

    // Chiffrement du mot de passe
    const { encrypted, initialisation_vector } = encryptPassword(
      password_hash,
      masterKey,
    );
    console.log("password_hash:", password_hash);
    console.log("masterKey:", masterKey);

    console.log("Encrypted password:", encrypted);
    console.log("IV:", initialisation_vector);

    await model.createPassword({
      user_id,
      service_name,
      login,
      password_hash: encrypted,
      iv: initialisation_vector,
    });

    res.status(201).json({ message: "Informations ajoutées" });
  } catch (error) {
    res.status(500).json({
      message: "Erreur serveur lors de la création des données",
      error: error.message,
    });
  }
};

export const getAll = async (req, res) => {
  try {
    const user_id = req.user.id;
    const masterkey = getUserKey(user_id);

    if (!masterkey) {
      return res.status(401).json({
        message: "Session crypto expirée",
      });
    }

    const entries = await model.getAllPasswords(user_id);

    if (!entries) {
      return res.status(404).json({ message: "annonce introuvable" });
    }
    const decryptedEntries = entries.map((entry) => {
      if (!entry.password_hash || !entry.iv) {
        return { ...entry, password: null }; // si données manquantes
      }

      try {
        const decrypted = decryptPassword(
          entry.password_hash,
          entry.iv,
          masterkey,
        );
        return { ...entry, password: decrypted };
      } catch (error) {
        console.error(
          "Erreur décryptage pour l'entrée ID",
          entry.id,
          error.message,
        );
        return { ...entry, password: null };
      }
    });

    res.json(decryptedEntries);
  } catch (error) {
    console.error("Erreur lors de la récupération des données:", error.message);
    res
      .status(500)
      .json({ message: "Erreur serveur lors de la récupération des données" });
  }
};

export const getById = async (req, res) => {
  try {
    const { id } = req.params;
    const user_id = req.user.id;

    const masterkey = getUserKey(user_id);

    if (!masterkey) {
      return res.status(401).json({
        message: "Session crypto expirée",
      });
    }

    const entry = await model.getPasswordById(id);

    if (!entry) {
      return res.status(404).json({ message: "annonce introuvable" });
    }

    const decryptedPassword = decryptPassword(
      entry.password_hash,
      entry.iv,
      masterkey,
    );

    res.json({
      ...entry,
      password: decryptedPassword,
    });
  } catch (error) {
    console.error(
      "Erreur lors de la récupération des données par id :",
      error.message,
    );
    res.status(500).json({
      message: "Erreur serveur lors de la récupération des données par id",
    });
  }
};

export const updateById = async (req, res) => {
  try {
    const { id } = req.params;
    const user_id = req.user.id;
    const existing = await model.getPasswordById(id);

    if (!existing || existing.user_id !== user_id) {
      return res.status(404).json({ message: "Donnée introuvable" });
    }

    const masterKey = getUserKey(user_id);

    if (!masterKey) {
      return res.status(401).json({
        message: "Session crypto expirée",
      });
    }

    let passwordEncrypted = existing.password_hash;
    let iv = existing.iv;

    if (req.body.password) {
      const encryptedData = encryptPassword(req.body.password, masterKey);
      passwordEncrypted = encryptedData.encrypted;
      iv = encryptedData.initialisation_vector;
    }

    const updatedData = {
      user_id,
      service_name: req.body.service_name ?? existing.service_name,
      login: req.body.login ?? existing.login,
      password_hash: passwordEncrypted,
      iv,
    };

    await model.updatePasswordById(id, updatedData);

    res.json({ message: "infos mises à jour", updatedData });
  } catch (error) {
    console.error(
      "Erreur lors de la mise à jour des données par id :",
      error.message,
    );
    res.status(500).json({
      message: "Erreur serveur lors de la mise a jour des données par id",
    });
  }
};

export const deleteById = async (req, res) => {
  try {
    const { id } = req.params;
    const user_id = req.user.id;

    const existing = await model.getPasswordById(id);

    if (!existing || existing.user_id !== user_id) {
      return res.status(404).json({ message: "donnée introuvable" });
    }
    await model.deletePasswordById(id);

    res.json({ message: "données supprimées" });
  } catch (error) {
    console.error("Erreur lors de la suppression des données :", error.message);
    res
      .status(500)
      .json({ message: "Erreur serveur lors de la suppression des données" });
  }
};
