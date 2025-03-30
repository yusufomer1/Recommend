const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// TMDB API için ayarlar
const TMDB_API_KEY = process.env.TMDB_API_KEY;
const TMDB_BASE_URL = 'https://api.themoviedb.org/3';

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MySQL bağlantısı
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'film_oneri_db' // Ana veritabanı adı
});

// Veritabanına bağlan
db.connect((err) => {
    if (err) {
        console.error('Veritabanı bağlantı hatası:', err);
        return;
    }
    console.log('MySQL veritabanına bağlandı!');

    // Kullanıcılar tablosunu oluştur (yoksa)
    const createUsersTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    `;
    db.query(createUsersTableQuery, (err) => {
        if (err) console.error('Kullanıcılar tablosu oluşturma hatası:', err);
        else console.log('Kullanıcılar tablosu hazır!');
    });

    // İzleme listesi tablosunu oluştur (yoksa)
    const createWatchlistTableQuery = `
    CREATE TABLE IF NOT EXISTS watchlist (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      movie_id INT NOT NULL,
      added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
      UNIQUE KEY user_movie_unique_wl (user_id, movie_id) /* Kullanıcı aynı filmi birden ekleyemesin */
    )
    `;
    db.query(createWatchlistTableQuery, (err) => {
        if (err) console.error('İzleme listesi tablosu oluşturma hatası:', err);
        else console.log('İzleme listesi tablosu hazır!');
    });

    // İzlenenler listesi tablosunu oluştur (yoksa)
    const createWatchedTableQuery = `
    CREATE TABLE IF NOT EXISTS watched (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      movie_id INT NOT NULL,
      watched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
      UNIQUE KEY user_movie_unique_wd (user_id, movie_id) /* Kullanıcı aynı filmi birden izlendi işaretleyemesin */
    )
    `;
    db.query(createWatchedTableQuery, (err) => {
        if (err) console.error('İzlenenler listesi tablosu oluşturma hatası:', err);
        else console.log('İzlenenler listesi tablosu hazır!');
    });

    // Favoriler tablosu (Gelecek için yorum satırı)
    /*
    const createFavoritesTableQuery = `
    CREATE TABLE IF NOT EXISTS favorites (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      movie_id INT NOT NULL,
      added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
      UNIQUE KEY user_movie_unique_fav (user_id, movie_id)
    )
    `;
    db.query(createFavoritesTableQuery, (err) => {
        if (err) console.error('Favoriler tablosu oluşturma hatası:', err);
        else console.log('Favoriler tablosu hazır!');
    });
    */
});

// JWT Token oluşturma fonksiyonu
const generateToken = (user) => {
    return jwt.sign(
        { id: user.id, username: user.username, email: user.email },
        process.env.JWT_SECRET || 'gizli_anahtar',
        { expiresIn: '24h' }
    );
};

// Token doğrulama middleware'i
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token bulunamadı!' });

    jwt.verify(token, process.env.JWT_SECRET || 'gizli_anahtar', (err, user) => {
        if (err) {
            console.error("Token doğrulama hatası:", err.message);
            if (err.name === 'TokenExpiredError') return res.status(403).json({ message: 'Oturum süresi doldu.' });
            return res.status(403).json({ message: 'Geçersiz token!' });
        }
        req.user = user; // user bilgisini request'e ekle
        next();
    });
};


// === KULLANICI ROTALARI ===
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) return res.status(400).json({ message: 'Tüm alanlar gereklidir!' });
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) return res.status(400).json({ message: 'Geçerli bir email adresi giriniz!' });
        if (password.length < 6) return res.status(400).json({ message: 'Şifre en az 6 karakter olmalıdır!' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';

        db.query(query, [username, email, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Bu kullanıcı adı veya email zaten kullanılıyor!' });
                console.error('Kayıt veritabanı hatası:', err);
                return res.status(500).json({ message: 'Sunucu hatası!' });
            }

            db.query('SELECT id, username, email, created_at FROM users WHERE id = ?', [result.insertId], (err, rows) => {
                if (err || rows.length === 0) {
                    console.error('Yeni kullanıcı bilgisi alınamadı:', err);
                    return res.status(500).json({ message: 'Kullanıcı bilgileri alınamadı!' });
                }
                const user = rows[0];
                const token = generateToken(user);
                res.status(201).json({
                    message: 'Kullanıcı başarıyla oluşturuldu!',
                    token,
                    user: { id: user.id, username: user.username, email: user.email, created_at: user.created_at }
                });
            });
        });
    } catch (error) {
        console.error('Kayıt genel hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası!' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: 'Tüm alanlar gereklidir!' });

        const query = 'SELECT id, username, email, password, created_at FROM users WHERE username = ? OR email = ?';
        db.query(query, [username, username], async (err, results) => {
            if (err) {
                console.error('Giriş veritabanı hatası:', err);
                return res.status(500).json({ message: 'Sunucu hatası!' });
            }
            if (results.length === 0) return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya şifre!' });

            const user = results[0];
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya şifre!' });

            const token = generateToken(user);
            res.json({
                message: 'Giriş başarılı!',
                token,
                user: { id: user.id, username: user.username, email: user.email, created_at: user.created_at }
            });
        });
    } catch (error) {
        console.error('Giriş genel hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası!' });
    }
});

app.get('/api/profile', authenticateToken, (req, res) => {
    // Token'dan çözülen kullanıcı bilgileri req.user içinde gelir
    res.json({
        message: 'Profil bilgileri başarıyla alındı',
        user: req.user
    });
});


// === FİLM ROTALARI (TMDB) ===
app.get('/api/movies/popular', async (req, res) => {
    try {
        const totalPages = parseInt(req.query.totalPages) || 10; // İlk 10 sayfa gibi
        const allMovies = [];
        for (let i = 1; i <= totalPages; i++) {
            const response = await axios.get(`${TMDB_BASE_URL}/movie/popular`, {
                params: { api_key: TMDB_API_KEY, language: 'tr-TR', page: i }
            });
            allMovies.push(...response.data.results);
        }
        res.json({ results: allMovies });
    } catch (error) {
        console.error('TMDB API popüler film hatası:', error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({
            message: 'Popüler filmler alınırken bir hata oluştu.'
        });
    }
});

app.get('/api/movies/:id', async (req, res) => {
    try {
        const movieId = req.params.id;
        const response = await axios.get(`${TMDB_BASE_URL}/movie/${movieId}`, {
            params: {
                api_key: TMDB_API_KEY,
                language: 'tr-TR',
                append_to_response: 'credits,videos' // İhtiyaca göre eklentiler
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('TMDB API film detay hatası:', error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({
            message: 'Film detayları alınırken bir hata oluştu.'
        });
    }
});


// === İZLEME LİSTESİ (WATCHLIST) ROTALARI ===
app.post('/api/watchlist', authenticateToken, async (req, res) => {
    const loggedInUserId = req.user.id;
    const { movieId } = req.body;
    if (!movieId) return res.status(400).json({ message: 'Film ID eksik.' });

    console.log(`Backend: İzleme listesine ekleme isteği: user=${loggedInUserId}, movie=${movieId}`);
    const checkQuery = 'SELECT id FROM watchlist WHERE user_id = ? AND movie_id = ?';
    db.query(checkQuery, [loggedInUserId, movieId], (checkErr, checkResults) => {
        if (checkErr) return res.status(500).json({ message: 'Sunucu hatası (kontrol)!' });
        if (checkResults.length > 0) return res.status(409).json({ message: 'Bu film zaten izleme listenizde.' });

        const insertQuery = 'INSERT INTO watchlist (user_id, movie_id) VALUES (?, ?)';
        db.query(insertQuery, [loggedInUserId, movieId], (err, result) => {
            if (err) {
                console.error('İzleme listesine ekleme hatası:', err);
                return res.status(500).json({ message: 'Sunucu hatası (ekleme)!' });
            }
            console.log(`Backend: Film ${movieId}, kullanıcı ${loggedInUserId} izleme listesine eklendi.`);
            res.status(201).json({ message: 'Film izleme listesine başarıyla eklendi!' });
        });
    });
});

app.get('/api/watchlist/:userId', authenticateToken, async (req, res) => {
    const requestedUserId = parseInt(req.params.userId);
    const loggedInUserId = req.user.id;
    if (requestedUserId !== loggedInUserId) return res.status(403).json({ message: 'Bu listeye erişim yetkiniz yok.' });

    console.log(`Backend: İzleme listesi alınıyor: userId=${requestedUserId}`);
    try {
        // Frontend'in film detaylarını alabilmesi için movie_id'yi seç
        const query = `SELECT id, user_id, movie_id, added_at FROM watchlist WHERE user_id = ? ORDER BY added_at DESC`;
        db.query(query, [requestedUserId], (err, results) => {
            if (err) {
                console.error('İzleme listesi alma hatası:', err);
                return res.status(500).json({ message: 'Sunucu hatası!' });
            }
            console.log(`Backend: İzleme listesi sonuçları (${requestedUserId}): ${results.length} adet`);
            // Doğrudan sonuç dizisini gönder: [{id: 1, user_id:X, movie_id: Y, added_at: ...}, ...]
            res.json(results);
        });
    } catch (error) {
        console.error('İzleme listesi alma genel hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası!' });
    }
});

app.delete('/api/watchlist/:userId/:movieId', authenticateToken, async (req, res) => {
    const requestedUserId = parseInt(req.params.userId);
    const movieIdToDelete = parseInt(req.params.movieId);
    const loggedInUserId = req.user.id;
    if (requestedUserId !== loggedInUserId) return res.status(403).json({ message: 'Bu işlem için yetkiniz yok.' });
    if (!movieIdToDelete) return res.status(400).json({ message: 'Film ID eksik.' });

    console.log(`Backend: İzleme listesinden silme isteği: user=${loggedInUserId}, movie=${movieIdToDelete}`);
    try {
        const query = 'DELETE FROM watchlist WHERE user_id = ? AND movie_id = ?';
        db.query(query, [loggedInUserId, movieIdToDelete], (err, result) => {
            if (err) {
                console.error('İzleme listesinden silme hatası:', err);
                return res.status(500).json({ message: 'Sunucu hatası!' });
            }
            if (result.affectedRows === 0) return res.status(404).json({ message: 'Film izleme listesinde bulunamadı.' });
            console.log(`Backend: Film ${movieIdToDelete}, kullanıcı ${loggedInUserId} izleme listesinden silindi.`);
            res.status(200).json({ message: 'Film izleme listesinden başarıyla kaldırıldı!' });
        });
    } catch (error) {
        console.error('İzleme listesinden silme genel hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası!' });
    }
});


// === İZLENENLER (WATCHED) ROTALARI ===
app.post('/api/watched', authenticateToken, async (req, res) => {
    const loggedInUserId = req.user.id;
    const { movieId } = req.body;
    if (!movieId) return res.status(400).json({ message: 'Film ID eksik.' });

    console.log(`Backend: İzlenenlere ekleme isteği: user=${loggedInUserId}, movie=${movieId}`);
    const checkQuery = 'SELECT id FROM watched WHERE user_id = ? AND movie_id = ?';
    db.query(checkQuery, [loggedInUserId, movieId], (checkErr, checkResults) => {
        if (checkErr) return res.status(500).json({ message: 'Sunucu hatası (kontrol)!' });
        if (checkResults.length > 0) return res.status(409).json({ message: 'Bu film zaten izlenenler listenizde.' });

        const insertQuery = 'INSERT INTO watched (user_id, movie_id) VALUES (?, ?)';
        db.query(insertQuery, [loggedInUserId, movieId], (err, result) => {
            if (err) {
                console.error('İzlenenlere ekleme hatası:', err);
                return res.status(500).json({ message: 'Sunucu hatası (ekleme)!' });
            }
            console.log(`Backend: Film ${movieId}, kullanıcı ${loggedInUserId} izlenenler listesine eklendi.`);
            res.status(201).json({ message: 'Film izlenenler listesine başarıyla eklendi!' });
        });
    });
});

app.get('/api/watched/:userId', authenticateToken, async (req, res) => {
    const requestedUserId = parseInt(req.params.userId);
    const loggedInUserId = req.user.id;
    if (requestedUserId !== loggedInUserId) return res.status(403).json({ message: 'Bu listeye erişim yetkiniz yok.' });

    console.log(`Backend: İzlenenler listesi alınıyor: userId=${requestedUserId}`);
    try {
        const query = `SELECT id, user_id, movie_id, watched_at FROM watched WHERE user_id = ? ORDER BY watched_at DESC`;
        db.query(query, [requestedUserId], (err, results) => {
            if (err) {
                console.error('İzlenenler listesi alma hatası:', err);
                return res.status(500).json({ message: 'Sunucu hatası!' });
            }
            console.log(`Backend: İzlenenler listesi sonuçları (${requestedUserId}): ${results.length} adet`);
            // Doğrudan sonuç dizisini gönder
            res.json(results);
        });
    } catch (error) {
        console.error('İzlenenler listesi alma genel hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası!' });
    }
});

app.delete('/api/watched/:userId/:movieId', authenticateToken, async (req, res) => {
    const requestedUserId = parseInt(req.params.userId);
    const movieIdToDelete = parseInt(req.params.movieId);
    const loggedInUserId = req.user.id;
    if (requestedUserId !== loggedInUserId) return res.status(403).json({ message: 'Yetkiniz yok.' });
    if (!movieIdToDelete) return res.status(400).json({ message: 'Film ID eksik.' });

    console.log(`Backend: İzlenenlerden silme isteği: user=${loggedInUserId}, movie=${movieIdToDelete}`);
    try {
        const query = 'DELETE FROM watched WHERE user_id = ? AND movie_id = ?';
        db.query(query, [loggedInUserId, movieIdToDelete], (err, result) => {
            if (err) {
                console.error('İzlenenlerden silme hatası:', err);
                return res.status(500).json({ message: 'Sunucu hatası!' });
            }
            if (result.affectedRows === 0) return res.status(404).json({ message: 'Film izlenenler listesinde bulunamadı.' });
            console.log(`Backend: Film ${movieIdToDelete}, kullanıcı ${loggedInUserId} izlenenler listesinden silindi.`);
            res.status(200).json({ message: 'Film izlenenler listesinden başarıyla kaldırıldı!' });
        });
    } catch (error) {
        console.error('İzlenenlerden silme genel hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası!' });
    }
});

// === FAVORİLER ROTALARI ===
// Şimdilik yorum satırı
/*
app.post('/api/favorites', authenticateToken, ...);
app.get('/api/favorites/:userId', authenticateToken, ...);
app.delete('/api/favorites/:userId/:movieId', authenticateToken, ...);
*/


// === İSTATİSTİK ROTASI (DETAYLI LOGLARLA GÜNCELLENDİ) ===
app.get('/api/stats/:userId', authenticateToken, async (req, res) => {
    const requestedUserIdParam = req.params.userId; // String olarak al
    const loggedInUserId = req.user.id; // Token'dan gelen ID

    // Log 1: Rota başlangıcı ve gelen parametre
    console.log(`\n--- [DEBUG /api/stats] Rota Başladı ---`);
    console.log(`[DEBUG /api/stats] Gelen req.params.userId: '${requestedUserIdParam}' (tip: ${typeof requestedUserIdParam})`);
    console.log(`[DEBUG /api/stats] Giriş Yapan Kullanıcı ID (Token'dan): ${loggedInUserId} (tip: ${typeof loggedInUserId})`);

    const requestedUserId = parseInt(requestedUserIdParam); // Sayıya çevir

    // Log 2: Sayıya çevrilmiş ID
    console.log(`[DEBUG /api/stats] Sayıya Çevrilmiş requestedUserId: ${requestedUserId} (tip: ${typeof requestedUserId})`);

    // Güvenlik Kontrolü
    if (isNaN(requestedUserId)) {
        console.error('[DEBUG /api/stats] !!! HATA: requestedUserId sayıya çevrilemedi (NaN) !!!');
        return res.status(400).json({ message: 'Geçersiz Kullanıcı ID formatı.' });
    }
    if (requestedUserId !== loggedInUserId) {
        console.warn(`[DEBUG /api/stats] !!! YETKİ HATASI: İsteyen (${loggedInUserId}), İstenen (${requestedUserId}) farklı!`);
        return res.status(403).json({ message: 'Başka bir kullanıcının istatistiklerine erişim yetkiniz yok.' });
    }

    try {
        // Sorguları tanımla
        const watchlistQuery = 'SELECT COUNT(*) AS count FROM watchlist WHERE user_id = ?';
        const watchedQuery = 'SELECT COUNT(*) AS count FROM watched WHERE user_id = ?';

        // Log 3: Çalıştırılacak sorgular ve parametreler
        console.log(`[DEBUG /api/stats] Watchlist Sorgusu Hazır: "${watchlistQuery}" - Parametre: [${requestedUserId}]`);
        console.log(`[DEBUG /api/stats] Watched Sorgusu Hazır: "${watchedQuery}" - Parametre: [${requestedUserId}]`);

        // 1. Watchlist Sayım Sorgusu
        console.log(`[DEBUG /api/stats] --> Watchlist Sayım Sorgusu Çalıştırılıyor...`);
        db.query(watchlistQuery, [requestedUserId], (errWl, resultsWl) => {
            // Log 4: Watchlist sorgu sonucu (hata veya başarı)
            if (errWl) {
                console.error('[DEBUG /api/stats] !!! VERİTABANI HATASI (Watchlist Sayım) !!!:', errWl);
                return res.status(500).json({ message: 'İstatistik alınamadı (Watchlist sorgu hatası).' });
            }
            console.log('[DEBUG /api/stats] <-- Watchlist Sayım Sorgu Başarılı. Ham Sonuç (resultsWl):', JSON.stringify(resultsWl));

            // Log 5: Watchlist sayısını hesapla
            let watchlistCount = 0; // Varsayılan değer
            if (resultsWl && Array.isArray(resultsWl) && resultsWl.length > 0 && resultsWl[0] && typeof resultsWl[0].count !== 'undefined') {
                watchlistCount = resultsWl[0].count;
            } else {
                console.warn('[DEBUG /api/stats] Beklenen `count` değeri watchlist sonucunda bulunamadı veya format yanlış.');
            }
            console.log(`[DEBUG /api/stats] Hesaplanan Watchlist Count: ${watchlistCount}`);

            // 2. Watched Sayım Sorgusu
            console.log(`[DEBUG /api/stats] --> Watched Sayım Sorgusu Çalıştırılıyor...`);
            db.query(watchedQuery, [requestedUserId], (errWd, resultsWd) => {
                // Log 6: Watched sorgu sonucu (hata veya başarı)
                if (errWd) {
                    console.error('[DEBUG /api/stats] !!! VERİTABANI HATASI (Watched Sayım) !!!:', errWd);
                    return res.status(500).json({ message: 'İstatistik alınamadı (Watched sorgu hatası).' });
                }
                console.log('[DEBUG /api/stats] <-- Watched Sayım Sorgu Başarılı. Ham Sonuç (resultsWd):', JSON.stringify(resultsWd));

                // Log 7: Watched sayısını hesapla
                let watchedCount = 0;
                if (resultsWd && Array.isArray(resultsWd) && resultsWd.length > 0 && resultsWd[0] && typeof resultsWd[0].count !== 'undefined') {
                    watchedCount = resultsWd[0].count;
                } else {
                    console.warn('[DEBUG /api/stats] Beklenen `count` değeri watched sonucunda bulunamadı veya format yanlış.');
                }
                console.log(`[DEBUG /api/stats] Hesaplanan Watched Count: ${watchedCount}`);

                // Sonuç objesini oluştur
                const stats = {
                    watchlistCount: watchlistCount,
                    watchedCount: watchedCount,
                    totalWatched: watchedCount, // totalWatched, watchedCount ile aynı
                    favoriteGenre: 'Bilinmiyor', // Bu daha sonra hesaplanabilir
                    totalWatchTime: 0 // Bu daha sonra hesaplanabilir
                };
                console.log(`[DEBUG /api/stats] Frontend'e Gönderilecek Son Stats Obj.:`, stats);
                console.log(`--- [DEBUG /api/stats] Rota Tamamlandı ---`);
                res.json(stats); // Sonucu frontend'e gönder
            });
        });
    } catch (error) {
        // Log 9: Genel try-catch hatası
        console.error(`[DEBUG /api/stats] !!! GENEL HATA (try-catch blogu) !!!:`, error);
        console.log(`--- [DEBUG /api/stats] Rota Hata İle Tamamlandı ---`);
        res.status(500).json({ message: 'Beklenmedik bir sunucu hatası oluştu.' });
    }
});


// Sunucuyu başlat
app.listen(PORT, () => {
    console.log(`Sunucu ${PORT} portunda çalışıyor!`);
});