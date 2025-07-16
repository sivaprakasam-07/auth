const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Debug: Check if JWT_SECRET is loaded
console.log('JWT_SECRET loaded:', process.env.JWT_SECRET ? 'Yes' : 'No');

// Register
exports.register = async (req, res) => {
  const { email, password } = req.body;
  const userExists = await User.findOne({ email });
  if (userExists) return res.status(400).json({ message: 'User already exists' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.create({ email, password: hashedPassword });

  res.status(201).json({ message: 'User registered' });
};

// Login
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: 'Invalid password' });

    // Check if JWT_SECRET exists
    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET is undefined!');
      return res.status(500).json({ message: 'Server configuration error' });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET,);
    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Protected Route
exports.protected = (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  // Check if JWT_SECRET exists
  if (!process.env.JWT_SECRET) {
    console.error('JWT_SECRET is undefined!');
    return res.status(500).json({ message: 'Server configuration error' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ message: 'Protected route accessed', user: decoded });
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

//token expiring
// { expiresIn: '2s' }




// const User = require('../models/userModel');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');

// // Debug: Check if secrets are loaded
// console.log('JWT_SECRET loaded:', process.env.JWT_SECRET ? 'Yes' : 'No');
// console.log('JWT_REFRESH_SECRET loaded:', process.env.JWT_REFRESH_SECRET ? 'Yes' : 'No');

// //Register a new user
// exports.register = async (req, res) => {
//   const { email, password } = req.body;
//   const userExists = await User.findOne({ email });
//   if (userExists) return res.status(400).json({ message: 'User already exists' });

//   const hashedPassword = await bcrypt.hash(password, 10);
//   const user = await User.create({ email, password: hashedPassword });

//   res.status(201).json({ message: 'User registered' });
// };

// //Login and issue access + refresh tokens
// exports.login = async (req, res) => {
//   try {
//     const { email, password } = req.body;
//     const user = await User.findOne({ email });
//     if (!user) return res.status(404).json({ message: 'User not found' });

//     const valid = await bcrypt.compare(password, user.password);
//     if (!valid) return res.status(401).json({ message: 'Invalid password' });

//     if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
//       return res.status(500).json({ message: 'Server configuration error' });
//     }

//     const accessToken = jwt.sign(
//       { id: user._id, email: user.email },
//       process.env.JWT_SECRET,
//       { expiresIn: '5s' } // for demo
//     );

//     const refreshToken = jwt.sign(
//       { id: user._id, email: user.email },
//       process.env.JWT_REFRESH_SECRET,
//       { expiresIn: '2m' }
//     );

//     res.json({
//       message: 'Login successful',
//       accessToken,
//       refreshToken
//     });
//   } catch (error) {
//     console.error('Login error:', error);
//     res.status(500).json({ message: 'Server error' });
//   }
// };

// // Protected route (requires valid access token)
// exports.protected = (req, res) => {
//   const authHeader = req.headers.authorization;
//   const token = authHeader?.split(' ')[1];

//   if (!token) return res.status(401).json({ message: 'Unauthorized' });

//   if (!process.env.JWT_SECRET) {
//     return res.status(500).json({ message: 'Server configuration error' });
//   }

//   try {
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     res.json({ message: 'Protected route accessed', user: decoded });
//   } catch (err) {
//     res.status(401).json({ message: 'Invalid or expired token' });
//   }
// };

// //Refresh access token using refresh token
// exports.refreshAccessToken = (req, res) => {
//   const { refreshToken } = req.body;
//   if (!refreshToken) return res.status(401).json({ message: 'No refresh token provided' });

//   try {
//     const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
//     const newAccessToken = jwt.sign(
//       { id: decoded.id, email: decoded.email },
//       process.env.JWT_SECRET,
//       { expiresIn: '2m' } // renew access token
//     );
//     res.json({ accessToken: newAccessToken });
//   } catch (err) {
//     res.status(403).json({ message: 'Invalid or expired refresh token' });
//   }
// };
