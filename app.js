const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const db = new sqlite3.Database('mi_base_de_datos.db');

// Crear tabla de usuarios si no existe
db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");

// Crear tabla de datos si no existe
db.run("CREATE TABLE IF NOT EXISTS data (id INTEGER PRIMARY KEY, entry1 TEXT, entry2 TEXT, entry3 TEXT)");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');

app.use(session({
    secret: 'tu_secreto_aqui',
    resave: false,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
    (username, password, done) => {
        db.get('SELECT password FROM users WHERE username = ?', [username], (err, row) => {
            if (err) {
                console.error(err); // <- Ver el error en consola si lo hay
                return done(err);
            }
            if (!row) return done(null, false, { message: 'Usuario no encontrado' });
            if (bcrypt.compareSync(password, row.password)) return done(null, { username: username });
            return done(null, false, { message: 'Contraseña incorrecta' });
        });
    }
));


passport.serializeUser((user, done) => {
    done(null, user.username);
});

passport.deserializeUser((username, done) => {
    done(null, {username: username});
});

// Rutas
app.get('/', (req, res) => {
    res.render('inicio');
});

app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/formulario');
    }
    res.redirect('/login');
});

app.get('/registro', (req, res) => {
    res.render('registro');
});

app.post('/registro', (req, res) => {
    const hash = bcrypt.hashSync(req.body.password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [req.body.username, hash], err => {
        if (err) {
            console.error(err); // <- Ver el error en consola si lo hay
            return res.send('Error al registrar.');
        }
        console.log('Usuario registrado con éxito.'); // <- Mensaje de éxito
        res.redirect('/login');
    });
});

app.get('/login', (req, res) => {
    res.render('login', { query: req.query });
});


app.post('/login', passport.authenticate('local', {
    successRedirect: '/formulario',
    failureRedirect: '/login',
    failureRedirect: '/login?error=1'
 // <- Esto permitirá que se muestren mensajes de error
}));

app.get('/formulario', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    res.render('formulario');
});

app.post('/formulario', (req, res) => {
    const { entry1, entry2, entry3 } = req.body;
    db.run("INSERT INTO data (entry1, entry2, entry3) VALUES (?, ?, ?)", [entry1, entry2, entry3], err => {
        if (err) return res.send('Error al guardar.');
        res.send('Gracias');
    });
});

app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/login');
});


app.listen(3000, () => {
    console.log('Aplicación corriendo en http://localhost:3001');
});
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Aplicación corriendo en http://localhost:${PORT}`);
});
