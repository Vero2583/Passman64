import mysql from "mysql2/promise"
import 'dotenv/config'

let db; 
const env = process.env

try {
   
    db = mysql.createPool({
        host: env.DB_HOST,
        user: env.DB_USER,
        database: env.DB_NAME
    })

    await db.getConnection();
    console.log(`connexion à la base de données ${env.DB_NAME} réussie`);

} catch (error) {
    console.error(`Erreur de la connexion à la base de données`, error.message)
    process.exit(1)
}


export {db}