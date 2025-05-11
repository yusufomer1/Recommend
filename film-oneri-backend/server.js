// server.js - Film Uygulaması Backend

// === IMPORTS ===
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const axios = require('axios'); // For TMDB API calls
require('dotenv').config(); // Load environment variables from .env file

// === INITIALIZATION ===
const app = express();
const PORT = process.env.PORT || 5000;

// === TMDB API SETTINGS ===
const TMDB_API_KEY = process.env.TMDB_API_KEY;
if (!TMDB_API_KEY) {
    console.warn("UYARI: TMDB_API_KEY .env dosyasında tanımlanmamış. Film API çağrıları başarısız olabilir.");
}
const TMDB_BASE_URL = 'https://api.themoviedb.org/3';
const TMDB_IMAGE_BASE_URL = 'https://image.tmdb.org/t/p/';

// === MIDDLEWARE ===
app.use(cors()); // Enable Cross-Origin Resource Sharing for all origins
app.use(bodyParser.json()); // Parse incoming JSON request bodies

// === MYSQL DATABASE CONNECTION ===
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'kayıtapp'
});

// === CONNECT TO DATABASE AND SETUP TABLES ===
db.connect((err) => {
    if (err) {
        console.error('!!! VERİTABANI BAĞLANTI HATASI:', err);
        console.error("Lütfen veritabanı sunucusunun çalıştığından ve .env dosyasındaki bilgilerin (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME) doğru olduğundan emin olun.");
        process.exit(1); // Exit the process if DB connection fails
    }
    console.log('MySQL veritabanına başarıyla bağlanıldı!');

    // --- Table Creation Queries ---

    // 1. Create Users Table (if not exists)
    const createUsersTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(100) NOT NULL, -- Store hashed passwords
      avatar_url VARCHAR(255),       -- URL for the user's avatar image
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;
    db.query(createUsersTableQuery, (err) => {
        if (err) console.error('HATA: Users tablosu oluşturulamadı:', err);
        else console.log('Users tablosu hazır.');
    });

    // 2. Create Watchlist Table (if not exists)
    const createWatchlistTableQuery = `
    CREATE TABLE IF NOT EXISTS watchlist (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,       -- Foreign key to users table
      movie_id INT NOT NULL,      -- TMDB movie ID
      added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE, -- If user is deleted, remove their watchlist items
      UNIQUE KEY user_movie_unique_wl (user_id, movie_id) -- Prevent adding the same movie multiple times per user
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;
    db.query(createWatchlistTableQuery, (err) => {
        if (err) console.error('HATA: Watchlist tablosu oluşturulamadı:', err);
        else console.log('Watchlist tablosu hazır.');
    });

    // 3. Create Watched Table (if not exists)
    const createWatchedTableQuery = `
    CREATE TABLE IF NOT EXISTS watched (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,       -- Foreign key to users table
      movie_id INT NOT NULL,      -- TMDB movie ID
      watched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE, -- If user is deleted, remove their watched items
      UNIQUE KEY user_movie_unique_wd (user_id, movie_id) -- Prevent marking the same movie as watched multiple times per user
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;
    db.query(createWatchedTableQuery, (err) => {
        if (err) console.error('HATA: Watched tablosu oluşturulamadı:', err);
        else console.log('Watched tablosu hazır.');
    });

    // 4. Create Comments Table (if not exists)
    //    Depends on the 'users' table existing due to the FOREIGN KEY.
    const createCommentsTableQuery = `
    CREATE TABLE IF NOT EXISTS comments (
      id INT AUTO_INCREMENT PRIMARY KEY,
      movie_id INT NOT NULL,          -- TMDB movie ID (we don't strictly need a foreign key to an external API)
      user_id INT NOT NULL,           -- Foreign key to our users table
      comment_text TEXT NOT NULL,     -- The content of the comment
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE, -- If user is deleted, remove their comments
      INDEX movie_idx (movie_id)      -- Index for faster lookup of comments by movie ID
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;
    db.query(createCommentsTableQuery, (err) => {
        if (err) console.error('HATA: Comments tablosu oluşturulamadı:', err);
        else console.log('Comments tablosu hazır!');
    });

    // 5. Create Ratings Table (if not exists)
    //    Depends on the 'users' table existing.
    const createRatingsTableQuery = `
    CREATE TABLE IF NOT EXISTS ratings (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      movie_id INT NOT NULL,             -- TMDB movie ID
      rating_value TINYINT UNSIGNED NOT NULL, -- Assuming 1-10 rating scale
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, -- Automatically update timestamp on modification
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE, -- If user deleted, remove their ratings
      UNIQUE KEY user_movie_rating_unique (user_id, movie_id), -- A user can rate a movie only once
      INDEX movie_rating_idx (movie_id), -- Index for faster lookup of ratings by movie
      CONSTRAINT chk_rating_value CHECK (rating_value >= 1 AND rating_value <= 10) -- Ensure rating is between 1 and 10
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;
    db.query(createRatingsTableQuery, (err) => {
        if (err) console.error('HATA: Ratings tablosu oluşturulamadı:', err);
        else console.log('Ratings tablosu hazır!');
    });

}); // End of db.connect callback

// === HELPER FUNCTIONS ===

/**
 * Generates a JWT token for a user.
 * Includes essential user details in the payload.
 * @param {object} user - The user object from the database (must include id, username, email, avatar_url, created_at).
 * @returns {string|null} The generated JWT token or null on error.
 */
const generateToken = (user) => {
    if (!user || !user.id || !user.username || !user.email) {
        console.error("[generateToken] Error: User object is missing required fields:", user);
        return null;
    }
    const payload = {
        id: user.id,
        username: user.username,
        email: user.email,
        avatar_url: user.avatar_url,
        created_at: user.created_at
    };
    console.log("[generateToken] Token payload oluşturuluyor:", payload);
    try {
        return jwt.sign(
            payload,
            process.env.JWT_SECRET || 'varsayilan_cok_guclu_gizli_anahtar',
            { expiresIn: '24h' }
        );
    } catch (error) {
        console.error("[generateToken] Token oluşturma hatası:", error);
        return null;
    }
};

// === MIDDLEWARE DEFINITIONS ===

/**
 * Middleware to authenticate requests using JWT.
 * Verifies the token from the 'Authorization: Bearer <token>' header.
 * Attaches the decoded user payload to `req.user` if valid.
 */
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!token) {
        console.log("[Auth Middleware] Token bulunamadı.");
        return res.status(401).json({ message: 'Kimlik doğrulama tokenı gereklidir.' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'varsayilan_cok_guclu_gizli_anahtar', (err, userPayload) => {
        if (err) {
            console.error("[Auth Middleware] Token doğrulama hatası:", err.name, err.message);
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Oturum süresi doldu. Lütfen tekrar giriş yapın.' });
            }
            return res.status(403).json({ message: 'Geçersiz veya bozuk token.' });
        }
        req.user = userPayload;
        console.log(`[Auth Middleware] Token doğrulandı: Kullanıcı ID ${userPayload.id} (${userPayload.username})`);
        next();
    });
};

// === API ROUTES ===

// --- USER AUTHENTICATION & PROFILE ROUTES ---

// POST /api/register - Register a new user
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password, avatarUrl } = req.body;
        console.log("[REGISTER] Gelen istek:", { username, email, avatarUrl });

        // Input Validation
        if (!username || !email || !password || !avatarUrl) {
            console.log("[REGISTER] Hata: Eksik alanlar.");
            return res.status(400).json({ message: 'Kullanıcı adı, e-posta, şifre ve avatar URLsi gereklidir.' });
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            console.log("[REGISTER] Hata: Geçersiz e-posta formatı.");
            return res.status(400).json({ message: 'Lütfen geçerli bir e-posta adresi girin.' });
        }
        if (password.length < 6) {
             console.log("[REGISTER] Hata: Şifre çok kısa.");
            return res.status(400).json({ message: 'Şifre en az 6 karakter uzunluğunda olmalıdır.' });
        }
        if (!avatarUrl.startsWith('http://') && !avatarUrl.startsWith('https://')) {
            console.log("[REGISTER] Hata: Geçersiz avatar URL formatı.");
             return res.status(400).json({ message: 'Lütfen geçerli bir avatar URLsi girin (http:// veya https:// ile başlamalıdır).' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const insertQuery = 'INSERT INTO users (username, email, password, avatar_url) VALUES (?, ?, ?, ?)';

        db.query(insertQuery, [username, email.toLowerCase(), hashedPassword, avatarUrl], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    const field = err.message.includes(username) ? 'Kullanıcı adı' : 'E-posta';
                     console.log(`[REGISTER] Hata: ${field} zaten kullanımda.`);
                    return res.status(409).json({ message: `${field} zaten kullanımda.` });
                }
                console.error('[REGISTER] Veritabanı hatası:', err);
                return res.status(500).json({ message: 'Kayıt sırasında sunucu hatası oluştu.' });
            }

            const selectQuery = 'SELECT id, username, email, avatar_url, created_at FROM users WHERE id = ?';
            db.query(selectQuery, [result.insertId], (selectErr, rows) => {
                if (selectErr || rows.length === 0) {
                    console.error('[REGISTER] Yeni kaydedilen kullanıcı alınamadı:', selectErr || 'Kullanıcı bulunamadı');
                    return res.status(201).json({
                         message: 'Kullanıcı başarıyla kaydedildi, ancak otomatik giriş için detaylar alınamadı.',
                         userId: result.insertId
                    });
                }

                const newUser = rows[0];
                const token = generateToken(newUser);

                if (!token) {
                     console.error('[REGISTER] Token oluşturulamadı.');
                     return res.status(201).json({
                         message: 'Kullanıcı başarıyla kaydedildi, ancak token oluşturulamadı.',
                         user: {
                            id: newUser.id,
                            username: newUser.username,
                            email: newUser.email,
                            avatar_url: newUser.avatar_url,
                            created_at: newUser.created_at
                         }
                     });
                }

                console.log(`[REGISTER] Kullanıcı ${newUser.username} (ID: ${newUser.id}) başarıyla kaydedildi ve token oluşturuldu.`);
                res.status(201).json({
                    message: 'Kullanıcı başarıyla kaydedildi!',
                    token,
                    user: {
                        id: newUser.id,
                        username: newUser.username,
                        email: newUser.email,
                        avatar_url: newUser.avatar_url,
                        created_at: newUser.created_at
                    }
                });
            });
        });
    } catch (error) {
        console.error('[REGISTER] Genel Hata:', error);
        res.status(500).json({ message: 'Kayıt sırasında beklenmedik bir sunucu hatası oluştu.' });
    }
});

// POST /api/login - Log in a user
app.post('/api/login', async (req, res) => {
    try {
        const { usernameOrEmail, password } = req.body;
        console.log("[LOGIN] Gelen istek:", { usernameOrEmail });

        if (!usernameOrEmail || !password) {
             console.log("[LOGIN] Hata: Eksik alanlar.");
            return res.status(400).json({ message: 'Kullanıcı adı/E-posta ve şifre gereklidir.' });
        }

        const query = 'SELECT id, username, email, password, avatar_url, created_at FROM users WHERE username = ? OR email = ?';
        db.query(query, [usernameOrEmail, usernameOrEmail.toLowerCase()], async (err, results) => {
            if (err) {
                console.error('[LOGIN] Veritabanı hatası:', err);
                return res.status(500).json({ message: 'Giriş sırasında sunucu hatası oluştu.' });
            }
            if (results.length === 0) {
                console.log("[LOGIN] Hata: Kullanıcı bulunamadı.");
                return res.status(401).json({ message: 'Geçersiz kimlik bilgileri.' });
            }

            const user = results[0];
            const passwordMatch = await bcrypt.compare(password, user.password);

            if (!passwordMatch) {
                console.log(`[LOGIN] Hata: Kullanıcı ${user.username} için şifre eşleşmedi.`);
                return res.status(401).json({ message: 'Geçersiz kimlik bilgileri.' });
            }

            const token = generateToken(user);

             if (!token) {
                console.error(`[LOGIN] Kullanıcı ${user.username} için token oluşturulamadı.`);
                return res.status(500).json({ message: 'Giriş başarılı, ancak token oluşturulamadı.' });
            }

            console.log(`[LOGIN] Kullanıcı ${user.username} (ID: ${user.id}) başarıyla giriş yaptı.`);
            res.json({
                message: 'Giriş başarılı!',
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    avatar_url: user.avatar_url,
                    created_at: user.created_at
                }
            });
        });
    } catch (error) {
        console.error('[LOGIN] Genel Hata:', error);
        res.status(500).json({ message: 'Giriş sırasında beklenmedik bir sunucu hatası oluştu.' });
    }
});

// GET /api/profile - Get logged-in user's profile info from the JWT token
app.get('/api/profile', authenticateToken, (req, res) => {
    console.log(`[PROFILE] Token'dan profil bilgisi istendi: Kullanıcı ${req.user.username} (ID: ${req.user.id})`);
    res.json({
        message: 'Profil bilgisi token\'dan başarıyla alındı.',
        user: req.user
    });
});


// --- AVATAR ROUTES ---

// GET /api/avatars - Get potential avatar images (movie posters) from TMDB
app.get('/api/avatars', async (req, res) => {
    console.log("[AVATARS] TMDB'den avatar seçenekleri isteniyor...");
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/popular`, {
            params: {
                api_key: TMDB_API_KEY,
                language: 'en-US', // Avatars are usually generic posters
                page: 1
            }
        });

        const avatars = response.data.results
            .filter(movie => movie.poster_path)
            .map(movie => ({
                id: movie.id, // Keep TMDB movie ID for reference if needed
                url: `${TMDB_IMAGE_BASE_URL}w200${movie.poster_path}`
            }))
            .slice(0, 20); // Limit the number of avatars

        console.log(`[AVATARS] ${avatars.length} avatar seçeneği bulundu.`);
        res.json(avatars);

    } catch (error) {
        console.error('[AVATARS] TMDB\'den avatar alınırken hata:', error.response ? error.response.data : error.message);
        const status = error.response ? error.response.status : 500;
        res.status(status).json({ message: 'Avatar seçenekleri alınırken bir hata oluştu.' });
    }
});

// PUT /api/users/me/avatar - Logged-in user updates their own avatar URL
app.put('/api/users/me/avatar', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { newAvatarUrl } = req.body;

    console.log(`[AVATAR UPDATE] Kullanıcı ${userId} tarafından avatar güncelleme isteği.`);
    console.log(`[AVATAR UPDATE] Gelen yeni URL: ${newAvatarUrl}`);

    if (!newAvatarUrl || typeof newAvatarUrl !== 'string') {
         console.log('[AVATAR UPDATE] Hata: Geçersiz veya eksik URL.');
        return res.status(400).json({ message: 'Yeni avatar URLsi gereklidir ve bir metin olmalıdır.' });
    }
    if (!newAvatarUrl.startsWith('http://') && !newAvatarUrl.startsWith('https://')) {
        console.log('[AVATAR UPDATE] Hata: Geçersiz URL formatı.');
         return res.status(400).json({ message: 'Lütfen geçerli bir avatar URLsi girin (http:// veya https:// ile başlamalıdır).' });
    }

    const query = 'UPDATE users SET avatar_url = ? WHERE id = ?';
    db.query(query, [newAvatarUrl, userId], (err, result) => {
        if (err) {
            console.error('[AVATAR UPDATE] Veritabanı hatası:', err);
            return res.status(500).json({ message: 'Avatar güncellenirken bir sunucu hatası oluştu.' });
        }

        if (result.affectedRows === 0) {
            // This case should ideally not happen if authenticateToken works correctly
            // and the user exists in the DB, but it's a good safeguard.
            console.warn(`[AVATAR UPDATE] Kullanıcı ${userId} bulunamadı (token geçerli olmasına rağmen).`);
            return res.status(404).json({ message: 'Güncellenecek kullanıcı bulunamadı.' });
        }

        console.log(`[AVATAR UPDATE] Başarılı: Kullanıcı ${userId} için avatar güncellendi.`);
        res.json({
             message: 'Avatar başarıyla güncellendi!',
             newAvatarUrl: newAvatarUrl // Return the new URL for the client to update its state
        });
    });
});


// --- TMDB MOVIE ROUTES ---

// GET /api/movies/popular - Get popular movies from TMDB
app.get('/api/movies/popular', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        console.log(`[MOVIES POPULAR] Sayfa ${page} için popüler filmler isteniyor...`);
        const response = await axios.get(`${TMDB_BASE_URL}/movie/popular`, {
            params: {
                api_key: TMDB_API_KEY,
                language: 'tr-TR',
                page: page
            }
        });
        console.log(`[MOVIES POPULAR] Sayfa ${page} için ${response.data.results?.length ?? 0} film bulundu.`);
        res.json(response.data);
    } catch (error) {
        console.error('[MOVIES POPULAR] TMDB\'den popüler filmler alınırken hata:', error.response ? error.response.data : error.message);
        const status = error.response ? error.response.status : 500;
        res.status(status).json({ message: 'Popüler filmler alınırken bir hata oluştu.' });
    }
});

// GET /api/movies/:id - Get details for a specific movie from TMDB
app.get('/api/movies/:id', async (req, res) => {
    const movieId = req.params.id;
     console.log(`[MOVIE DETAILS] ${movieId} ID'li film detayları isteniyor...`);

    if (!/^\d+$/.test(movieId)) { // Basic validation for numeric ID
         console.log('[MOVIE DETAILS] Hata: Geçersiz Film ID formatı.');
        return res.status(400).json({ message: 'Geçersiz film ID formatı.' });
    }

    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/${movieId}`, {
            params: {
                api_key: TMDB_API_KEY,
                language: 'tr-TR',
                append_to_response: 'credits,videos' // Get cast, crew, and trailers
            }
        });
         console.log(`[MOVIE DETAILS] ${movieId} ID'li film detayları başarıyla alındı.`);
        res.json(response.data);
    } catch (error) {
        console.error(`[MOVIE DETAILS] ${movieId} ID'li film detayları alınırken hata:`, error.response ? error.response.data : error.message);
        const status = error.response ? error.response.status : 500;
        const message = status === 404 ? 'Film bulunamadı.' : 'Film detayları alınamadı.';
        res.status(status).json({ message });
    }
});

// --- WATCHLIST ROUTES ---

// POST /api/watchlist - Add a movie to the logged-in user's watchlist
app.post('/api/watchlist', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { movieId } = req.body;
    console.log(`[WATCHLIST ADD] Kullanıcı ${userId}, film ${movieId} ekleme isteği.`);

    if (!movieId || typeof movieId !== 'number' || movieId <= 0) {
         console.log('[WATCHLIST ADD] Hata: Geçersiz Film ID.');
        return res.status(400).json({ message: 'Geçerli bir Film IDsi gereklidir.' });
    }

    const query = 'INSERT INTO watchlist (user_id, movie_id) VALUES (?, ?)';
    db.query(query, [userId, movieId], (err, result) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                console.log(`[WATCHLIST ADD] Film ${movieId}, Kullanıcı ${userId} listesinde zaten var.`);
                return res.status(409).json({ message: 'Bu film zaten izleme listenizde.' });
            }
            if (err.code === 'ER_NO_REFERENCED_ROW' || err.code === 'ER_NO_REFERENCED_ROW_2') {
                // This means the user_id doesn't exist, which shouldn't happen if authenticateToken works
                console.error(`[WATCHLIST ADD] Hata: Geçersiz kullanıcı ID ${userId}.`);
                return res.status(400).json({ message: 'Geçersiz kullanıcı referansı.' });
            }
            console.error('[WATCHLIST ADD] Veritabanı hatası:', err);
            return res.status(500).json({ message: 'İzleme listesine eklenirken sunucu hatası oluştu.' });
        }
        console.log(`[WATCHLIST ADD] Başarılı: Film ${movieId}, Kullanıcı ${userId} listesine eklendi.`);
        res.status(201).json({ message: 'Film başarıyla izleme listesine eklendi!' });
    });
});

// GET /api/watchlist/:userId - Get a specific user's watchlist (movie IDs and added date)
app.get('/api/watchlist/:userId', authenticateToken, async (req, res) => {
    const requestedUserId = parseInt(req.params.userId, 10);
    const loggedInUserId = req.user.id;
    console.log(`[WATCHLIST GET] İstek sahibi ${loggedInUserId}, Kullanıcı ${requestedUserId} listesini istiyor.`);

    if (isNaN(requestedUserId)) {
        console.log('[WATCHLIST GET] Hata: Geçersiz Kullanıcı ID formatı.');
        return res.status(400).json({ message: 'Geçersiz Kullanıcı ID formatı.' });
    }
    // Ensure the logged-in user is requesting their own watchlist
    if (requestedUserId !== loggedInUserId) {
        console.warn(`[WATCHLIST GET] Yetkisiz Erişim: Kullanıcı ${loggedInUserId}, Kullanıcı ${requestedUserId} listesine erişmeye çalıştı.`);
        return res.status(403).json({ message: 'Bu izleme listesine erişim yetkiniz yok.' });
    }

    console.log(`[WATCHLIST GET] Kullanıcı ${requestedUserId} için izleme listesi alınıyor...`);
    const query = `SELECT movie_id, added_at FROM watchlist WHERE user_id = ? ORDER BY added_at DESC`;
    db.query(query, [requestedUserId], (err, results) => {
        if (err) {
            console.error('[WATCHLIST GET] Veritabanı hatası:', err);
            return res.status(500).json({ message: 'İzleme listesi alınırken sunucu hatası oluştu.' });
        }
        console.log(`[WATCHLIST GET] Kullanıcı ${requestedUserId} için ${results.length} öğe bulundu.`);
        res.json(results);
    });
});

// DELETE /api/watchlist/:userId/:movieId - Remove a movie from a user's watchlist
app.delete('/api/watchlist/:userId/:movieId', authenticateToken, async (req, res) => {
    const requestedUserId = parseInt(req.params.userId, 10);
    const movieIdToDelete = parseInt(req.params.movieId, 10);
    const loggedInUserId = req.user.id;
    console.log(`[WATCHLIST DELETE] İstek sahibi ${loggedInUserId}, Kullanıcı ${requestedUserId} listesinden film ${movieIdToDelete} silme isteği.`);

     if (isNaN(requestedUserId) || isNaN(movieIdToDelete)) {
         console.log('[WATCHLIST DELETE] Hata: Geçersiz Kullanıcı veya Film ID formatı.');
        return res.status(400).json({ message: 'Geçersiz Kullanıcı veya Film ID formatı.' });
    }
    if (requestedUserId !== loggedInUserId) {
        console.warn(`[WATCHLIST DELETE] Yetkisiz Erişim: Kullanıcı ${loggedInUserId}, Kullanıcı ${requestedUserId} listesinden silmeye çalıştı.`);
        return res.status(403).json({ message: 'Bu işlemi yapma yetkiniz yok.' });
    }

    console.log(`[WATCHLIST DELETE] Kullanıcı ${loggedInUserId} listesinden film ${movieIdToDelete} siliniyor...`);
    const query = 'DELETE FROM watchlist WHERE user_id = ? AND movie_id = ?';
    db.query(query, [loggedInUserId, movieIdToDelete], (err, result) => {
        if (err) {
            console.error('[WATCHLIST DELETE] Veritabanı hatası:', err);
            return res.status(500).json({ message: 'İzleme listesinden kaldırılırken sunucu hatası oluştu.' });
        }
        if (result.affectedRows === 0) {
            console.log(`[WATCHLIST DELETE] Film ${movieIdToDelete}, Kullanıcı ${loggedInUserId} listesinde bulunamadı.`);
            return res.status(404).json({ message: 'Film izleme listenizde bulunamadı.' });
        }
        console.log(`[WATCHLIST DELETE] Başarılı: Film ${movieIdToDelete}, Kullanıcı ${loggedInUserId} listesinden silindi.`);
        res.status(200).json({ message: 'Film başarıyla izleme listesinden kaldırıldı!' });
    });
});

// --- WATCHED LIST ROUTES ---

// POST /api/watched - Add a movie to the logged-in user's watched list
app.post('/api/watched', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { movieId } = req.body;
    console.log(`[WATCHED ADD] Kullanıcı ${userId}, film ${movieId} ekleme isteği.`);

    if (!movieId || typeof movieId !== 'number' || movieId <= 0) {
         console.log('[WATCHED ADD] Hata: Geçersiz Film ID.');
        return res.status(400).json({ message: 'Geçerli bir Film IDsi gereklidir.' });
    }

    const query = 'INSERT INTO watched (user_id, movie_id) VALUES (?, ?)';
    db.query(query, [userId, movieId], (err, result) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                console.log(`[WATCHED ADD] Film ${movieId}, Kullanıcı ${userId} listesinde zaten var.`);
                return res.status(409).json({ message: 'Bu film zaten izlendi olarak işaretlenmiş.' });
            }
            if (err.code === 'ER_NO_REFERENCED_ROW' || err.code === 'ER_NO_REFERENCED_ROW_2') {
                 console.error(`[WATCHED ADD] Hata: Geçersiz kullanıcı ID ${userId}.`);
                return res.status(400).json({ message: 'Geçersiz kullanıcı referansı.' });
            }
            console.error('[WATCHED ADD] Veritabanı hatası:', err);
            return res.status(500).json({ message: 'İzlenenler listesine eklenirken sunucu hatası oluştu.' });
        }
        console.log(`[WATCHED ADD] Başarılı: Film ${movieId}, Kullanıcı ${userId} listesine eklendi.`);
        res.status(201).json({ message: 'Film başarıyla izlendi olarak işaretlendi!' });
    });
});

// GET /api/watched/:userId - Get a specific user's watched list (movie IDs and watched date)
app.get('/api/watched/:userId', authenticateToken, async (req, res) => {
    const requestedUserId = parseInt(req.params.userId, 10);
    const loggedInUserId = req.user.id;
    console.log(`[WATCHED GET] İstek sahibi ${loggedInUserId}, Kullanıcı ${requestedUserId} listesini istiyor.`);

     if (isNaN(requestedUserId)) {
        console.log('[WATCHED GET] Hata: Geçersiz Kullanıcı ID formatı.');
        return res.status(400).json({ message: 'Geçersiz Kullanıcı ID formatı.' });
    }
    if (requestedUserId !== loggedInUserId) {
        console.warn(`[WATCHED GET] Yetkisiz Erişim: Kullanıcı ${loggedInUserId}, Kullanıcı ${requestedUserId} listesine erişmeye çalıştı.`);
        return res.status(403).json({ message: 'Bu listeye erişim yetkiniz yok.' });
    }

    console.log(`[WATCHED GET] Kullanıcı ${requestedUserId} için izlenenler listesi alınıyor...`);
    const query = `SELECT movie_id, watched_at FROM watched WHERE user_id = ? ORDER BY watched_at DESC`;
    db.query(query, [requestedUserId], (err, results) => {
        if (err) {
            console.error('[WATCHED GET] Veritabanı hatası:', err);
            return res.status(500).json({ message: 'İzlenenler listesi alınırken sunucu hatası oluştu.' });
        }
         console.log(`[WATCHED GET] Kullanıcı ${requestedUserId} için ${results.length} öğe bulundu.`);
        res.json(results);
    });
});

// DELETE /api/watched/:userId/:movieId - Remove a movie from a user's watched list
app.delete('/api/watched/:userId/:movieId', authenticateToken, async (req, res) => {
    const requestedUserId = parseInt(req.params.userId, 10);
    const movieIdToDelete = parseInt(req.params.movieId, 10);
    const loggedInUserId = req.user.id;
     console.log(`[WATCHED DELETE] İstek sahibi ${loggedInUserId}, Kullanıcı ${requestedUserId} listesinden film ${movieIdToDelete} silme isteği.`);

    if (isNaN(requestedUserId) || isNaN(movieIdToDelete)) {
         console.log('[WATCHED DELETE] Hata: Geçersiz Kullanıcı veya Film ID formatı.');
        return res.status(400).json({ message: 'Geçersiz Kullanıcı veya Film ID formatı.' });
    }
    if (requestedUserId !== loggedInUserId) {
        console.warn(`[WATCHED DELETE] Yetkisiz Erişim: Kullanıcı ${loggedInUserId}, Kullanıcı ${requestedUserId} listesinden silmeye çalıştı.`);
        return res.status(403).json({ message: 'Bu işlemi yapma yetkiniz yok.' });
    }

    console.log(`[WATCHED DELETE] Kullanıcı ${loggedInUserId} listesinden film ${movieIdToDelete} siliniyor...`);
    const query = 'DELETE FROM watched WHERE user_id = ? AND movie_id = ?';
    db.query(query, [loggedInUserId, movieIdToDelete], (err, result) => {
        if (err) {
            console.error('[WATCHED DELETE] Veritabanı hatası:', err);
            return res.status(500).json({ message: 'İzlenenler listesinden kaldırılırken sunucu hatası oluştu.' });
        }
        if (result.affectedRows === 0) {
            console.log(`[WATCHED DELETE] Film ${movieIdToDelete}, Kullanıcı ${loggedInUserId} listesinde bulunamadı.`);
            return res.status(404).json({ message: 'Film izlenenler listenizde bulunamadı.' });
        }
        console.log(`[WATCHED DELETE] Başarılı: Film ${movieIdToDelete}, Kullanıcı ${loggedInUserId} listesinden silindi.`);
        res.status(200).json({ message: 'Film başarıyla izlenenler listesinden kaldırıldı!' });
    });
});

// --- USER DETAILS & STATISTICS ROUTE (Combined) ---
// GET /api/users/:userId/details - Get profile details and list counts for a user.
app.get('/api/users/:userId/details', authenticateToken, async (req, res) => {
    const requestedUserIdParam = req.params.userId;
    const loggedInUserId = req.user.id;

    console.log(`[USER DETAILS] İstek sahibi ${loggedInUserId}, Kullanıcı ${requestedUserIdParam} detaylarını istiyor.`);

    const requestedUserId = parseInt(requestedUserIdParam, 10);

    if (isNaN(requestedUserId)) {
        console.error('[USER DETAILS] Hata: Geçersiz Kullanıcı ID formatı.');
        return res.status(400).json({ message: 'Geçersiz Kullanıcı ID formatı.' });
    }
    if (requestedUserId !== loggedInUserId) {
        console.warn(`[USER DETAILS] Yetkisiz Erişim: Kullanıcı ${loggedInUserId}, Kullanıcı ${requestedUserId} detaylarına erişmeye çalıştı.`);
        return res.status(403).json({ message: 'Bu kullanıcının detaylarına erişim yetkiniz yok.' });
    }

    try {
        const userQuery = 'SELECT id, username, email, avatar_url, created_at FROM users WHERE id = ?';
        console.log(`[USER DETAILS] Kullanıcı ${requestedUserId} için veritabanından detaylar alınıyor...`);
        db.query(userQuery, [requestedUserId], (errUser, userResults) => {
            if (errUser) {
                console.error('[USER DETAILS] Veritabanı Hatası (Kullanıcı Detayları):', errUser);
                return res.status(500).json({ message: 'Kullanıcı detayları alınamadı.' });
            }
            if (userResults.length === 0) {
                console.log(`[USER DETAILS] Kullanıcı ${requestedUserId} bulunamadı.`);
                return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
            }
            const userDetails = userResults[0];
            console.log('[USER DETAILS] Kullanıcı detayları başarıyla alındı:', userDetails);

            Promise.all([
                new Promise((resolve, reject) => {
                    const watchlistQuery = 'SELECT COUNT(*) AS count FROM watchlist WHERE user_id = ?';
                     console.log(`[USER DETAILS] Kullanıcı ${requestedUserId} için izleme listesi sayısı alınıyor...`);
                    db.query(watchlistQuery, [requestedUserId], (errWl, resultsWl) => {
                        if (errWl) {
                            console.error('[USER DETAILS] Veritabanı Hatası (İzleme Listesi Sayısı):', errWl);
                            reject('İzleme listesi sayısı alınamadı.');
                        } else {
                            resolve(resultsWl[0]?.count ?? 0);
                        }
                    });
                }),
                new Promise((resolve, reject) => {
                    const watchedQuery = 'SELECT COUNT(*) AS count FROM watched WHERE user_id = ?';
                    console.log(`[USER DETAILS] Kullanıcı ${requestedUserId} için izlenenler listesi sayısı alınıyor...`);
                    db.query(watchedQuery, [requestedUserId], (errWd, resultsWd) => {
                        if (errWd) {
                             console.error('[USER DETAILS] Veritabanı Hatası (İzlenenler Listesi Sayısı):', errWd);
                            reject('İzlenenler listesi sayısı alınamadı.');
                        } else {
                            resolve(resultsWd[0]?.count ?? 0);
                        }
                    });
                })
            ]).then(([watchlistCount, watchedCount]) => {
                console.log(`[USER DETAILS] İzleme Listesi Sayısı: ${watchlistCount}, İzlenenler Sayısı: ${watchedCount}`);
                const responsePayload = {
                    user: userDetails,
                    stats: {
                        watchlistCount: watchlistCount,
                        watchedCount: watchedCount,
                    }
                };
                console.log(`[USER DETAILS] Birleştirilmiş kullanıcı detayları ve istatistikler gönderiliyor:`, responsePayload);
                res.json(responsePayload);

            }).catch(statsError => {
                console.error('[USER DETAILS] İstatistikler alınırken hata:', statsError);
                 res.status(500).json({
                    message: `Kullanıcı detayları alındı, ancak istatistikler alınamadı: ${statsError}`,
                    user: userDetails,
                    stats: null
                 });
            });
        });

    } catch (error) {
        console.error(`[USER DETAILS] Genel hata:`, error);
        res.status(500).json({ message: 'Kullanıcı detayları ve istatistikleri alınırken beklenmedik bir sunucu hatası oluştu.' });
    }
});

// --- COMMENT ROUTES ---

// GET /api/movies/:movieId/comments - Get comments for a specific movie
app.get('/api/movies/:movieId/comments', async (req, res) => {
    const movieIdParam = req.params.movieId;
     console.log(`[COMMENTS GET] ${movieIdParam} ID'li film için yorumlar isteniyor...`);

    const movieId = parseInt(movieIdParam, 10);
    if (isNaN(movieId)) {
        console.log('[COMMENTS GET] Hata: Geçersiz Film ID formatı.');
        return res.status(400).json({ message: 'Geçersiz Film ID formatı.' });
    }

    const query = `
        SELECT
            c.id, c.movie_id, c.user_id, c.comment_text, c.created_at,
            u.username, u.avatar_url
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.movie_id = ?
        ORDER BY c.created_at DESC;
    `;

    db.query(query, [movieId], (err, results) => {
        if (err) {
            console.error(`[COMMENTS GET] Film ${movieId} için yorumlar alınırken veritabanı hatası:`, err);
            return res.status(500).json({ message: 'Yorumlar alınırken sunucu hatası oluştu.' });
        }
        console.log(`[COMMENTS GET] Film ${movieId} için ${results.length} yorum bulundu.`);
        res.json(results);
    });
});

// POST /api/movies/:movieId/comments - Add a new comment to a movie (requires login)
app.post('/api/movies/:movieId/comments', authenticateToken, async (req, res) => {
    const movieIdParam = req.params.movieId;
    const userId = req.user.id;
    const { commentText } = req.body;
     console.log(`[COMMENT POST] Kullanıcı ${userId}, film ${movieIdParam} için yorum ekleme isteği.`);

    const movieId = parseInt(movieIdParam, 10);
    if (isNaN(movieId)) {
        console.log('[COMMENT POST] Hata: Geçersiz Film ID.');
        return res.status(400).json({ message: 'Geçersiz Film ID formatı.' });
    }
    if (!commentText || typeof commentText !== 'string' || commentText.trim() === '') {
        console.log('[COMMENT POST] Hata: Yorum metni eksik veya boş.');
        return res.status(400).json({ message: 'Yorum içeriği boş olamaz.' });
    }
    const trimmedComment = commentText.trim();
    if (trimmedComment.length > 1000) { // Max comment length
         console.log('[COMMENT POST] Hata: Yorum çok uzun.');
         return res.status(400).json({ message: 'Yorum 1000 karakterden uzun olamaz.' });
    }

    const insertQuery = 'INSERT INTO comments (movie_id, user_id, comment_text) VALUES (?, ?, ?)';
    db.query(insertQuery, [movieId, userId, trimmedComment], (err, result) => {
        if (err) {
             if (err.code === 'ER_NO_REFERENCED_ROW' || err.code === 'ER_NO_REFERENCED_ROW_2') {
                console.error(`[COMMENT POST] Hata: Geçersiz kullanıcı ID ${userId} yorum eklerken.`);
                return res.status(400).json({ message: 'Yorum eklenemedi, geçersiz kullanıcı referansı.' });
            }
            console.error(`[COMMENT POST] Film ${movieId}, Kullanıcı ${userId} için yorum eklenirken veritabanı hatası:`, err);
            return res.status(500).json({ message: 'Yorum eklenirken sunucu hatası oluştu.' });
        }

        const newCommentId = result.insertId;
        console.log(`[COMMENT POST] Yorum başarıyla eklendi, ID: ${newCommentId}`);

        // Fetch the newly created comment with user details to return to the client
        const selectNewCommentQuery = `
            SELECT
                c.id, c.movie_id, c.user_id, c.comment_text, c.created_at,
                u.username, u.avatar_url
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.id = ?;
        `;
        db.query(selectNewCommentQuery, [newCommentId], (selectErr, newCommentResult) => {
             if (selectErr || newCommentResult.length === 0) {
                 console.error('[COMMENT POST] Yeni eklenen yorum alınırken hata:', selectErr || 'Yorum ekleme sonrası bulunamadı');
                 // Still return 201 as the comment was inserted, but client won't get the full object
                 return res.status(201).json({ message: 'Yorum başarıyla eklendi!' });
             }
             console.log('[COMMENT POST] Yeni yorum detayları başarıyla alındı.');
             res.status(201).json(newCommentResult[0]);
        });
    });
});


// --- RATING ROUTES ---

// GET /api/movies/:movieId/my-rating - Get the logged-in user's rating for a specific movie
app.get('/api/movies/:movieId/my-rating', authenticateToken, async (req, res) => {
    const movieIdParam = req.params.movieId;
    const userId = req.user.id; // User ID from the authenticated token
    console.log(`[RATING GET] Kullanıcı ${userId}, film ${movieIdParam} için puanını istiyor.`);

    const movieId = parseInt(movieIdParam, 10);
    if (isNaN(movieId)) {
        console.log('[RATING GET] Hata: Geçersiz Film ID formatı.');
        return res.status(400).json({ message: 'Geçersiz Film ID formatı.' });
    }

    const query = 'SELECT rating_value FROM ratings WHERE user_id = ? AND movie_id = ?';
    db.query(query, [userId, movieId], (err, results) => {
        if (err) {
            console.error(`[RATING GET] Kullanıcı ${userId}, film ${movieId} için puan alınırken veritabanı hatası:`, err);
            return res.status(500).json({ message: 'Puan bilgisi alınırken sunucu hatası oluştu.' });
        }

        if (results.length > 0) {
            const ratingValue = results[0].rating_value;
            console.log(`[RATING GET] Kullanıcı ${userId}, film ${movieId} için puan bulundu: ${ratingValue}`);
            res.json({ rating: ratingValue }); // Return the rating value
        } else {
            console.log(`[RATING GET] Kullanıcı ${userId}, film ${movieId} için puan bulunamadı.`);
            res.json({ rating: null }); // Indicate no rating exists yet
        }
    });
});


// PUT /api/ratings - Add or update a movie rating for the logged-in user
app.put('/api/ratings', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { movieId, ratingValue } = req.body;

    console.log(`[RATING PUT] Kullanıcı ${userId}, film ${movieId} için puan ${ratingValue} verme/güncelleme isteği.`);

    // Input Validation
    const parsedMovieId = parseInt(movieId, 10);
    const parsedRatingValue = parseInt(ratingValue, 10);

    if (isNaN(parsedMovieId) || parsedMovieId <= 0) {
        console.log('[RATING PUT] Hata: Geçersiz Film ID.');
        return res.status(400).json({ message: 'Geçerli bir Film IDsi gereklidir.' });
    }
    if (isNaN(parsedRatingValue) || parsedRatingValue < 1 || parsedRatingValue > 10) {
        console.log(`[RATING PUT] Hata: Geçersiz puan değeri ${ratingValue}. 1-10 arasında olmalı.`);
        return res.status(400).json({ message: 'Puan 1 ile 10 arasında bir değer olmalıdır.' });
    }

    // Use INSERT ... ON DUPLICATE KEY UPDATE to handle both new ratings and updates
    const query = `
        INSERT INTO ratings (user_id, movie_id, rating_value)
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE
            rating_value = VALUES(rating_value),
            updated_at = CURRENT_TIMESTAMP;
    `;

    db.query(query, [userId, parsedMovieId, parsedRatingValue], (err, result) => {
        if (err) {
             if (err.code && err.code.includes('CHECK')) { // Check constraint violation (rating_value)
                 console.error(`[RATING PUT] Veritabanı Kısıtlama Hatası (Puan Aralığı):`, err);
                 return res.status(400).json({ message: 'Puan değeri veritabanı kısıtlamasına uymuyor (1-10).' });
             }
             if (err.code === 'ER_NO_REFERENCED_ROW' || err.code === 'ER_NO_REFERENCED_ROW_2') {
                console.error(`[RATING PUT] Hata: Geçersiz kullanıcı ID ${userId} puan eklerken/güncellerken.`);
                return res.status(400).json({ message: 'Puan kaydedilemedi, geçersiz kullanıcı referansı.' });
            }
            console.error(`[RATING PUT] Kullanıcı ${userId}, film ${parsedMovieId} için puan kaydedilirken veritabanı hatası:`, err);
            return res.status(500).json({ message: 'Puan kaydedilirken/güncellenirken sunucu hatası oluştu.' });
        }

        // result.affectedRows will be 1 if a new row was inserted,
        // and 2 if an existing row was updated (because ON DUPLICATE KEY UPDATE is treated as a DELETE then INSERT by MySQL in some cases, or 1 if only updated)
        // result.insertId will be the ID of the new row if inserted, or 0 if updated.
        const action = result.insertId !== 0 ? 'kaydedildi' : 'güncellendi';
        console.log(`[RATING PUT] Başarılı: Kullanıcı ${userId}, film ${parsedMovieId} için puan ${action}. Puan: ${parsedRatingValue}. Sonuç:`, result);

        res.status(200).json({
            message: `Puan başarıyla ${action}!`,
            rating: parsedRatingValue // Return the saved/updated rating
        });
    });
});

// === YENİ: FILM ÖNERİLERİ ROUTE ===
app.get('/api/recommendations', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    console.log(`[RECOMMENDATIONS] Kullanıcı ${userId} için film önerileri isteniyor.`);

    // This SQL query attempts to find movies that co-occur with the user's
    // watchlist items OR movies they've rated highly (e.g., 7+).
    // It then scores these potential recommendations based on the frequency of co-occurrence.
    // This is a simplified item-to-item collaborative filtering approach.
    const recommendationQuery = `
        WITH user_interest_movies AS (
            -- Movies the user has positively interacted with (watchlist OR high rating)
            SELECT movie_id FROM watchlist WHERE user_id = ?
            UNION -- DISTINCT union to avoid duplicate movie_ids if a movie is in both
            SELECT movie_id FROM ratings WHERE user_id = ? AND rating_value >= 7 -- Consider ratings >= 7 as "liked"
        ),
        co_occurrence_scores AS (
            -- Co-occurrences with watchlist items
            SELECT
                w2.movie_id AS recommended_movie_id,
                COUNT(*) AS score -- Each co-occurrence in watchlist gets 1 point
            FROM
                watchlist w1
            JOIN
                watchlist w2 ON w1.user_id != ? AND w1.movie_id IN (SELECT movie_id FROM user_interest_movies) AND w2.movie_id NOT IN (SELECT movie_id FROM user_interest_movies) -- w1 is from current user, w2 is from others
                               AND w1.movie_id != w2.movie_id -- Different movies
                               AND w2.user_id != ? -- Ensure w2 is from a *different* user
            WHERE
                 w2.movie_id NOT IN (SELECT movie_id FROM watched WHERE user_id = ?) -- Don't recommend already watched movies
            GROUP BY
                w2.movie_id

            UNION ALL -- Combine scores from watchlist and ratings co-occurrences

            -- Co-occurrences with highly rated movies
            SELECT
                r2.movie_id AS recommended_movie_id,
                COUNT(*) * 2 AS score -- Give higher weight to co-occurrence with rated items (e.g., 2 points)
            FROM
                ratings r1
            JOIN
                ratings r2 ON r1.user_id != ? AND r1.movie_id IN (SELECT movie_id FROM user_interest_movies) AND r2.movie_id NOT IN (SELECT movie_id FROM user_interest_movies)
                               AND r1.movie_id != r2.movie_id
                               AND r2.user_id != ? -- Ensure r2 is from a *different* user
            WHERE
                 r1.rating_value >= 7 AND r2.rating_value >= 7 -- Both users rated these movies highly
                 AND r2.movie_id NOT IN (SELECT movie_id FROM watched WHERE user_id = ?) -- Don't recommend already watched movies
            GROUP BY
                r2.movie_id
        )
        -- Aggregate scores, order, and limit
        SELECT
            cos.recommended_movie_id,
            SUM(cos.score) as final_score
        FROM co_occurrence_scores cos
        GROUP BY
            cos.recommended_movie_id
        ORDER BY
            final_score DESC
        LIMIT 10; -- Max 10 recommendations
    `;

    // Parameters for the SQL query's ? placeholders:
    // 1. user_interest_movies -> watchlist.user_id = ? (current userId)
    // 2. user_interest_movies -> ratings.user_id = ? (current userId)
    // 3. watchlist w1 JOIN watchlist w2 ON w1.user_id != ? (current userId, for w2.user_id condition)
    // 4. watchlist w2 JOIN watchlist w2 ON w2.user_id != ? (current userId, for w2.user_id condition)
    // 5. w2.movie_id NOT IN (SELECT movie_id FROM watched WHERE user_id = ?) (current userId)
    // 6. ratings r1 JOIN ratings r2 ON r1.user_id != ? (current userId, for r2.user_id condition)
    // 7. ratings r2 JOIN ratings r2 ON r2.user_id != ? (current userId, for r2.user_id condition)
    // 8. r2.movie_id NOT IN (SELECT movie_id FROM watched WHERE user_id = ?) (current userId)
    const queryParams = [userId, userId, userId, userId, userId, userId, userId, userId];

    db.query(recommendationQuery, queryParams, async (err, results) => {
        if (err) {
            console.error(`[RECOMMENDATIONS] Kullanıcı ${userId} için öneri alınırken veritabanı hatası:`, err);
            return res.status(500).json({ message: 'Film önerileri alınırken bir sunucu hatası oluştu.' });
        }

        if (results.length === 0) {
            console.log(`[RECOMMENDATIONS] Kullanıcı ${userId} için SQL tabanlı kişisel öneri bulunamadı. Popüler filmler önerilecek.`);
            try {
                // Fallback: Fetch popular movies from TMDB
                const popularMoviesResponse = await axios.get(`${TMDB_BASE_URL}/movie/popular`, {
                    params: { api_key: TMDB_API_KEY, language: 'tr-TR', page: 1 }
                });
                const popularMovies = popularMoviesResponse.data.results.slice(0, 10).map(movie => ({
                    id: movie.id,
                    title: movie.title,
                    poster_path: movie.poster_path,
                    overview: movie.overview,
                    vote_average: movie.vote_average
                    // Add any other fields your frontend expects for a movie item
                }));
                return res.json({
                    message: "Size özel aktif bir öneri bulunamadı. Daha fazla filmle etkileşimde bulundukça (izleme listesine ekleyip, puan verdikçe) size özel öneriler burada görünecektir. Şimdilik popüler filmleri listeledik:",
                    recommendations: popularMovies,
                    type: "popular_fallback"
                 });
            } catch (tmdbError) {
                console.error('[RECOMMENDATIONS] Popüler filmler fallback TMDB hatası:', tmdbError.response ? tmdbError.response.data : tmdbError.message);
                return res.status(500).json({ message: 'Film önerileri ve popüler filmler alınırken hata oluştu.' });
            }
        }

        console.log(`[RECOMMENDATIONS] Kullanıcı ${userId} için ${results.length} ham film ID'si bulundu (skorlarıyla):`, results);

        try {
            // Fetch details for each recommended movie ID from TMDB
            const recommendedMovieDetails = await Promise.all(
                results.map(async (row) => {
                    const movieId = row.recommended_movie_id;
                    try {
                        const tmdbResponse = await axios.get(`${TMDB_BASE_URL}/movie/${movieId}`, {
                            params: { api_key: TMDB_API_KEY, language: 'tr-TR' }
                        });
                        // Format the response to match what the frontend might expect
                        return {
                            id: tmdbResponse.data.id,
                            title: tmdbResponse.data.title,
                            poster_path: tmdbResponse.data.poster_path,
                            overview: tmdbResponse.data.overview,
                            vote_average: tmdbResponse.data.vote_average,
                            // Add other relevant fields like release_date, genres, etc.
                            recommendation_score: row.final_score // Optionally include the internal score
                        };
                    } catch (movieError) {
                        console.error(`[RECOMMENDATIONS] TMDB'den ${movieId} ID'li film detayı alınırken hata:`, movieError.response ? movieError.response.statusText : movieError.message);
                        return null; // If a movie detail fetch fails, return null to filter out later
                    }
                })
            );

            const validRecommendations = recommendedMovieDetails.filter(movie => movie !== null);
            console.log(`[RECOMMENDATIONS] Kullanıcı ${userId} için ${validRecommendations.length} geçerli film önerisi gönderiliyor.`);
            res.json({
                message: "İşte size özel film önerileri!",
                recommendations: validRecommendations,
                type: "personalized"
            });

        } catch (error) {
            console.error(`[RECOMMENDATIONS] Kullanıcı ${userId} için TMDB detayları alınırken genel hata:`, error);
            res.status(500).json({ message: 'Önerilen film detayları alınırken bir hata oluştu.' });
        }
    });
});

// --- LEGACY/OTHER STATS ROUTE ---
// GET /api/stats/:userId - Get user stats (watchlist/watched counts)
// NOTE: Kept for potential specific uses or legacy compatibility. Prefer /api/users/:userId/details.
app.get('/api/stats/:userId', authenticateToken, (req, res) => {
    const requestedUserId = parseInt(req.params.userId, 10);
    const loggedInUserId = req.user.id;
    console.log(`[STATS LEGACY] İstek sahibi ${loggedInUserId}, Kullanıcı ${requestedUserId} istatistiklerini istiyor.`);

    if (isNaN(requestedUserId)) {
        console.log('[STATS LEGACY] Hata: Geçersiz Kullanıcı ID formatı.');
        return res.status(400).json({ message: 'Geçersiz Kullanıcı ID formatı.' });
    }
    if (requestedUserId !== loggedInUserId) {
         console.warn(`[STATS LEGACY] Yetkisiz Erişim: Kullanıcı ${loggedInUserId}, Kullanıcı ${requestedUserId} istatistiklerine erişmeye çalıştı.`);
        return res.status(403).json({ message: 'Bu istatistiklere erişim yetkiniz yok.' });
    }

    const watchlistQuery = 'SELECT COUNT(*) AS count FROM watchlist WHERE user_id = ?';
    const watchedQuery = 'SELECT COUNT(*) AS count FROM watched WHERE user_id = ?';

    let stats = {};

    db.query(watchlistQuery, [requestedUserId], (errWl, resultsWl) => {
        if (errWl) {
            console.error('[STATS LEGACY] Veritabanı Hatası (İzleme Listesi):', errWl);
            return res.status(500).json({ message: 'İzleme listesi sayısı alınamadı.' });
        }
        stats.watchlistCount = resultsWl[0]?.count ?? 0;

        db.query(watchedQuery, [requestedUserId], (errWd, resultsWd) => {
            if (errWd) {
                console.error('[STATS LEGACY] Veritabanı Hatası (İzlenenler):', errWd);
                return res.status(500).json({ message: 'İzlenen sayısı alınamadı.' });
            }
            stats.watchedCount = resultsWd[0]?.count ?? 0;

            console.log(`[STATS LEGACY] Kullanıcı ${requestedUserId} için istatistikler gönderiliyor:`, stats);
            res.json(stats);
        });
    });
});


// === ROOT ROUTE ===
app.get('/', (req, res) => {
  res.send('Film Uygulaması Backend API Çalışıyor!');
});

// === NOT FOUND HANDLER (404) ===
app.use((req, res, next) => {
  console.log(`[404] Endpoint bulunamadı: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ message: `Endpoint bulunamadı: ${req.method} ${req.originalUrl}` });
});

// === GLOBAL ERROR HANDLER (500) ===
// This should be the last middleware
app.use((err, req, res, next) => {
  console.error("!!! GLOBAL ERROR HANDLER YAKALADI:", err.stack || err); // Log the stack trace
  res.status(err.status || 500).json({
       message: err.message || 'Sunucuda beklenmedik bir hata oluştu!',
       // Optionally, include error details in development
       // error: process.env.NODE_ENV === 'development' ? err : {}
    });
});

// === START SERVER ===
app.listen(PORT, () => {
    console.log(`---- Sunucu Başlatıldı ----`);
    console.log(`Port: ${PORT}`);
    console.log(`API Adresi: http://localhost:${PORT}`);
    console.log(`Ortam (Environment): ${process.env.NODE_ENV || 'development'}`);
    console.log(`---- Veritabanı Bilgileri ----`);
    console.log(`Host: ${process.env.DB_HOST || 'localhost'}`);
    console.log(`Veritabanı Adı: ${process.env.DB_NAME || 'kayıtapp'}`);
    console.log(`Kullanıcı: ${process.env.DB_USER || 'root'}`);
    console.log(`--------------------------`);
});