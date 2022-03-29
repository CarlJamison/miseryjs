const app = require('express')();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const port = process.env.PORT || 3000;

app.get('/controller', (req, res) => {
  res.sendFile(__dirname + '/misery-controller.html');
});
app.get('/client', (req, res) => {
  res.sendFile(__dirname + '/misery-client.html');
});

var customers = [];

var controllers = io.of("/controller")
var clients = io.of("/client")

controllers.on('connection', (socket) => {
  controllers.emit('connections', customers);
  socket.on('message', msg => {
    clients.emit('message', msg);
    console.log(msg);
  });

});

clients.on('connection', (socket) => {
  console.log("new connection: " + socket.id);
  socket.on('register', msg => {
    msg.id = socket.id;
    customers.push(msg);
    controllers.emit('connections', customers);
  });

  socket.on('disconnect', function() {
    console.log(socket.id + " disconnected");
    customers = customers.filter(c => c.id != socket.id);
    controllers.emit('connections', customers);
  });
});

http.listen(port, () => {
  console.log(`Socket.IO server running at http://localhost:${port}/`);
});
