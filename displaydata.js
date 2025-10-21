const express = require('express');


const session = require('express-session');


const cors = require('cors');

const app = express();
const port = 3000;


// Middleware to parse JSON requests
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cors({
    origin: 'https://Shreynik00.github.io',  // Allow your GitHub Pages site
    methods: ['GET', 'POST', 'PUT', 'DELETE'],  // Allow specific HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'],  // Allow specific headers
    credentials: true  // Allow credentials if needed
}));


// Handle preflight requests
app.options('*', cors());
app.use(session({
    secret: 'your-secret-key', // Replace with a secure secret
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true } // Ensure secure cookies if using HTTPS
}));



app.post('/apicall', async (req, res) => {
    try {
        const { number} = req.body;
        
        if (!number) {
            return res.status(400).json({ success: false, message: "mising number" });
        }

        const apiUrl = `https://authsure.in/api/mobile/lookup/${number}`;

        // Fetch data with headers (e.g. API key)
        const response = await fetch(apiUrl, {
          method: 'POST', // or 'POST' if required
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': 'ak_h183e2s52x53b4y1r711n3q2'  
          }
        });
    
        // Parse the response
        const data = await response.json();
    
        // Return the API response to the client
        res.json({ success: true, data });
    
      } catch (error) {
        console.error("Error fetching API:", error);
        res.status(500).json({ success: false, message: "Server error", error: error.message });
      }
    });

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
