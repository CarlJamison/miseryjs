var net = require("net");
var tcp_connections = [];
const { v4: uuidv4 } = require('uuid');

module.exports = {
    handlers: [
        {   //Write to TCP connection
            returnType: 5,
            handle: (scope, message) => {
                var cust = scope.customers.find(c => c.socketId == scope.socket.id);
                data = Buffer.from(message.output.data, 'base64');
                var serverId = `${message.output.host}:${message.output.port}-${cust.id}`;
                tcp_connections[serverId].connections[message.output.connectionId].write(data);
                return false;
            }
        },
        {   //Initialize
            returnType: 6,
            handle: (scope, msg) => {
                
                var cust = scope.customers.find(c => c.socketId == scope.socket.id);
                if(!cust){
                    return false;
                }

                var serverId = `${msg.output.host}:${msg.output.port}-${cust.id}`;

                var coolServer = tcp_connections[serverId]
                if(!coolServer || coolServer.server){
                    return false;  //Either not a valid server or already created
                }

                coolServer.jobId = msg.output.jobId;
                coolServer.server = net.createServer(tcp_sock => {
                    var id = uuidv4();
                    coolServer.connections[id] = tcp_sock;

                    tcp_sock.on("data", data => {
                        scope.clients.to(cust.socketId).emit("add-job-data", { 
                            id: coolServer.jobId.toString(),
                            connection_id: id, 
                            data: data.toString('base64') });
                    });
                
                    tcp_sock.on("end", () => {
                        tcp_connections[serverId].connections[id] = null;
                    });
                });

                coolServer.server.listen(coolServer.port, () => {
                    console.log(`TCP is initilized and running on port: ${coolServer.port}`);
                });
            }
        }
    ],
    listeners:[
        {
            //Create placeholder server
            name: 'create-tcp-server',
            handle: (scope, msg) => {
                var cust = scope.customers.find(c => c.id == msg.id);

                if(cust){
                    tcp_connections[`${msg.args[0]}:${msg.args[1]}-${msg.id}`] = {
                        port: msg.args[2],
                        connections: [],
                        jobId: null,
                        server: null,
                    }
                    scope.clients.to(cust.socketId).emit("run-stream", ["TcpProxy", msg.args[0], msg.args[1]]);
                    console.log("Created TCP Server - pending initialization: " + msg.args);
                }else{
                    scope.socket.emit('echo', 'Invalid client');
                }
            }
        }
        //TODO close connection
    ]

}