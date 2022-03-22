const app = require('express')();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const port = process.env.PORT || 3000;

var players = 1;
var connList = [];

app.get('/controller', (req, res) => {
  res.sendFile(__dirname + '/misery-controller.html');
});
app.get('/client', (req, res) => {
  res.sendFile(__dirname + '/misery-client.html');
});

app.get('/canvasSocket.js', (req, res) => {
  res.sendFile(__dirname + '/canvasSocket.js');
});

var controllers = io.of("/controller")
var clients = io.of("/client")

controllers.on('connection', (socket) => {

  var playerNumber = players;
  players++;

  socket.on('message', msg => {
    clients.emit('message', msg);
    console.log(msg);
  });
});

clients.on('connection', (socket) => {

});

http.listen(port, () => {
  console.log(`Socket.IO server running at http://localhost:${port}/`);
});
