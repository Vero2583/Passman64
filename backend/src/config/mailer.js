import nodemailer from "nodemailer"
import "dotenv/config"


//export const transporter = nodemailer.createTransport({
 //   host: process.env.BREVO_SMTP_HOST,
 //   port: Number(process.env.BREVO_SMTP_PORT),
 //   secure: false,
 //   auth: {
 //       user: process.env.BREVO_SMTP_USER,
 //       pass: process.env.BREVO_SMTP_PASS
 //   }
//})

//transporter.verify((err, success) => {
 //   if (err) console.error("Erreur SMTP", err.message)
 //       else console.log("SMTP connecté")
//})


export const sendVerificationEmail = async (email, token) => {
    await transporter.sendMail({
       from: 'Authentification API <vfraigneau64@gmail.com>',
        to: email,
        subject: 'Confirmez votre email',
        html: `<h2> Bienvenue ${email} ! </h2>
        <p> Merci pour votre inscription, veuillez cliquer sur le lien en dessous pour vérifier votre email: </p> <br/>
        <a href="http://localhost:3002/api/auth/verify?token=${token}">Vérifier son email</a>
        ` 
    })
}

export const sendResetPasswordEmail = async (email, token) => {

    await transporter.sendMail({
        from: 'Verification API  <vfraigneau64@gmail.com>',
        to: email,
        subject: 'Rénitialisation de la passwordé',
        html: `<h2>   Bienvenue ${email} ! </h2>
        <p> Cliquez sur le lien pour rénitialiser votre mot de passe :  </p> <br/>
        <a href="http://localhost:3002/api/auth/reset-password-request?token=${token}">rénitialiser votre mot de passe</a>`
    })
}