import app from "./app.js"
import 'dotenv/config'



const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
    console.log(`serveur toutrne sur http://localhost:${PORT}`);
});
