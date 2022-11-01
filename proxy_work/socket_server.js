const express = require('express');
const app = express();
const listener = require('http').Server(app, {
  maxHttpBufferSize: 1e8
});


// TCP socket server
const net = require("net");
const port = 5000;

const clients = require('socket.io')(listener);
listener.listen(8888, () => {
  console.log(`Listener server running at http://localhost:${8888}/`);
});


// pasted from index.js

customers = [];

clients.on('connection', (socket) => {
  console.log("new connection: " + socket.id);
  clients.to(socket.id).emit("echo", "welcome");

  // TCP socket code 
  const server = net.createServer((tcp_sock) => {
      console.log("Client connected");
  
      // TCP socket recv's some data ...
      tcp_sock.on("data", (data) => {
          const strData = data.toString();
          console.log(`TCP Server Received: ${strData}`);
          clients.to(socket.id).emit("echo", data.toString('base64'));
      });

      // websocket recv's some data
      socket.on('echo', msg => {
        data = Buffer.from(msg, 'base64');
        tcp_sock.write(data);
      });
  
      tcp_sock.on("end", () => {
          console.log("Client disconnected");
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

  socket.on('disconnect', function() {
    console.log(socket.id + " disconnected");
    // disconnect from socket
  });


});



