import express from 'express'
import {authMiddleware} from '../middlewares/auth.middleware.js'
import {create, getAll, getById, updateById, deleteById} from "../controllers/password.controller.js"
import { validatePassword } from '../middlewares/validation.middleware.js'

const router = express.Router()

// toutes les routes nécessitent un utilisateur connecté
router.use(authMiddleware)

//ajouter un mot de passe
router.post('/', validatePassword, create )

//récupérer tous les mots de passe
router.get('/', getAll)

//récupérer un mot de passe précis
router.get('/:id', getById )

//mettre à jour un mot de passe
router.put('/:id', validatePassword, updateById)

//supprimer un mot de passe
router.delete('/:id', deleteById)

export default router