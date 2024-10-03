const express = require('express');
const app = express();
const port = 81; // Port 80 for HTTP

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
