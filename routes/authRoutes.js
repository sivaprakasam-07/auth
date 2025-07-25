const express = require('express');
const router = express.Router();
const { register, login, protected: protectedRoute } = require('../controllers/authController');

router.post('/register', register);
router.post('/login', login);
// router.post('/refresh', refreshAccessToken);
router.get('/protected', protectedRoute);

module.exports = router;
// refreshAccessToken