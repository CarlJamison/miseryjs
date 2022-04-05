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
  socket.on('echo', msg => {
    var cust = customers.find(c => c.id == msg.id);
    if(cust){
      clients.to(cust.socketId).emit("echo", msg.message);
      console.log(cust.socketId + ": " + msg.message);
    }
  });

});

clients.on('connection', (socket) => {
  console.log("new connection: " + socket.id);
  socket.on('register', msg => {
    msg.socketId = socket.id;
    customers.push(msg);
    controllers.emit('connections', customers);
  });

  socket.on('disconnect', function() {
    console.log(socket.id + " disconnected");
    customers = customers.filter(c => c.socketId != socket.id);
    controllers.emit('connections', customers);
  });

  socket.on('echo', msg => {
    controllers.emit('echo', msg);
  });
});

http.listen(port, () => {
  console.log(`Socket.IO server running at http://localhost:${port}/`);
});
