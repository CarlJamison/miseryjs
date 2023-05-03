var net = require("net");
var tcp_connections = [];
const { v4: uuidv4 } = require('uuid');
const DEBUG = false;

module.exports = {
    handlers: [
        {   //Write to TCP connection
            returnType: 5,
            handle: (scope, message) => {
                var cust = scope.customers.find(c => c.socketId == scope.socket.id);
                if(!cust) return;
                if(DEBUG) console.log("Recieving: " );
                data = Buffer.from(message.output.data, 'base64');
                var serverId = `${message.output.host}:${message.output.port}-${cust.id}`;
                var connection = tcp_connections[serverId].connections[message.output.connectionId];
                if(connection){
                    connection.write(data);
                    if(DEBUG) console.log(message.output.connectionId + " : " + data);
                }
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
                        var strData = data.toString();
                        strData = strData.replace(`localhost:${coolServer.port}`, '{ClientHost}');
                        if(DEBUG) console.log("Writing: " + id + " : " + strData);

                        scope.clients.to(cust.socketId).emit("add-job-data", { 
                            id: coolServer.jobId.toString(),
                            connection_id: id, 
                            //data: Buffer.from(strData).toString('base64') })
                            data: data.toString('base64') });
                    });
                
                    tcp_sock.on("end", () => {
                        if(tcp_connections[serverId]){
                            tcp_connections[serverId].connections[id] = null;
                            scope.clients.to(cust.socketId).emit("add-job-data", { 
                                id: coolServer.jobId.toString(),
                                connection_id: id,
                            });
                        }  
                    });

                    tcp_sock.on("error", console.log);
                });

                coolServer.server.listen(coolServer.port, () => {
                    scope.controllers.emit('echo', `TCP is initialized and running on port: ${coolServer.port}`);
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

                if(Object.values(tcp_connections).find(c => c.port == msg.args[2])){
                    scope.socket.emit('echo', 'Server already exists');
                    return;
                }

                if(tcp_connections[`${msg.args[0]}:${msg.args[1]}-${msg.id}`]){
                    scope.socket.emit('echo', 'Proxy already exists');
                    return;
                }

                if(cust){
                    tcp_connections[`${msg.args[0]}:${msg.args[1]}-${msg.id}`] = {
                        port: msg.args[2],
                        connections: [],
                        jobId: null,
                        server: null,
                        id: `${msg.args[0]}:${msg.args[1]}-${msg.id}`
                    }
                    scope.clients.to(cust.socketId).emit("run-stream", ["Tcpproxy", msg.args[0], msg.args[1]]);
                    scope.socket.emit('echo', 'Tcp proxy initiated, awaiting job creation');
                }else{
                    scope.socket.emit('echo', 'Invalid client');
                }
            }
        },
        {
            //Create placeholder server
            name: 'close-tcp-server',
            handle: (scope, msg) => {

                var server = Object.values(tcp_connections).find(c => c.port == msg.args[0]);
                if(!server){
                    scope.socket.emit('echo', 'Server does not exist');
                    return;
                }
                
                var cust = scope.customers.find(c => c.id == msg.id);
                if(cust){
                    scope.clients.to(cust.socketId).emit("kill-job", [server.jobId]);
                    server.server.close();
                    delete tcp_connections[server.id];
                    scope.socket.emit('echo', `Server port ${msg.args[0]} closed`);
                }else{
                    scope.socket.emit('echo', 'Invalid client');
                }
            }
        },
        {
            //Create placeholder server
            name: 'get-tcp-servers',
            handle: (scope, msg) => {
                var connections = Object.keys(tcp_connections);
                if(connections.length){
                    connections.forEach(c => scope.socket.emit('echo', `${c} ${tcp_connections[c].port}`));
                }else{
                    scope.socket.emit('echo', 'No existing connections');
                }
            }
        }
    ]

}