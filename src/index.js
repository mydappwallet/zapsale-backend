require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.use('/auth', require('./routes/auth'));
app.use('/flows', require('./routes/flows'));

app.get('/', (req, res) => res.send('Lead Automation API'));

app.listen(process.env.PORT || 5000, () => {
  console.log('Server running on port 5000');
});