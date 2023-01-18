const express = require('express');
const app = express();
const net = require("net");
const listener = require('http').Server(app, {
  maxHttpBufferSize: 1e8
});
const port = 5000;

const clients = require('socket.io')(listener);
listener.listen(8000, () => {
  console.log(`Listener server running at http://localhost:${8000}/`);
});

var connectionCounter = 0;
var connections = [];

customers = [];

clients.on('connection', (socket) => {
  console.log("new connection: " + socket.id);

  socket.on('echo', msg => {
    data = Buffer.from(msg.data, 'base64');
    console.log(msg.id + " from: ");
    if(connections[msg.id])
      connections[msg.id].write(data);
  });
  
  socket.on('disconnect', () => {
    console.log(socket.id + " disconnected");
  });
});

// TCP socket code 
const server = net.createServer(tcp_sock => {
  console.log("Client connected");

  var id = connectionCounter++;
  connections[id] = tcp_sock;

  // TCP socket recv's some data ...
  tcp_sock.on("data", (data) => {
      var strData = data.toString();
      strData = strData.replace(`localhost:${port}`, '{ClientHost}');

      //console.log(`TCP Server Received:` + strData);
      clients.emit("echo", { id, data: Buffer.from(strData).toString('base64') });
  });

  tcp_sock.on("end", () => {
      console.log("Client disconnected");
      clients.emit("close", { id });
      connections[id] = null;
  });

  tcp_sock.on("error", (error) => {
      console.log(`Socket Error: ${error.message}`);
  });
});

server.on("error", (error) => {
  console.log(`Server Error: ${error.message}`);
});

server.listen(port, () => {
  console.log(`TCP socket server is running on port: ${port}`);
}); // end TCP socket code