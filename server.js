const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const app = express();

const session = require('express-session');
const cors = require('cors');

const dayjs = require('dayjs');
const utc = require('dayjs/plugin/utc');
dayjs.extend(utc);


const BD_OFFSET = 6 * 60; 

// Middleware for CORS
app.use(cors({
  origin: 'http://localhost:4444',   // Frontend origin
  credentials: true
}));

// Middleware to parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration (1 day validity)
app.use(session({
  secret: 'your-secret-key-please-change-this-in-production', 
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  }
}));

const PORT = process.env.PORT||4444;


// Serve static files (e.g., if we store profile pictures publicly)
app.use(express.static(path.join(__dirname, 'static')));

// Multer setup for file uploads (using memory storage for profile pictures)
const storage = multer.memoryStorage();
const upload = multer({ storage });

// MySQL connection pool setup
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '', 
  database: 'web_project',
});


// New login route to handle authentication
app.post('/api/login', async (req, res) => {
    const { username, password, userType } = req.body;

    // Input validation
    if (!username || !password || !userType) {
        return res.status(400).json({ message: 'Username, password, and user type are required.' });
    }

    let conn;
    try {
        conn = await pool.getConnection();

        // Find the user by username and user_type
        const [rows] = await conn.execute(
            'SELECT * FROM users WHERE username = ? AND user_type = ?',
            [username, userType]
        );
        
        const user = rows[0];

        // If user not found or user_type doesn't match
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials or user type.' });
        }

        // Compare the provided password with the hashed password in the database
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (passwordMatch) {
            // Password matches, create a session
            req.session.user = {
                user_id: user.user_id,
                username: user.username,
                user_type: user.user_type
            };

            // Respond with a success message and the user's type for frontend redirection
            res.status(200).json({ 
                message: 'Login successful!',
                user: {
                    user_id: user.user_id,
                    username: user.username,
                    user_type: user.user_type
                }
            });
        } else {
            // Password does not match
            res.status(401).json({ message: 'Invalid credentials.' });
        }

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    } finally {
        if (conn) {
            conn.release(); // Release the connection back to the pool
        }
    }
});






// A basic route to serve the HTML file. Place `index.html` in a `static` folder.
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'static', 'index.html'));
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
