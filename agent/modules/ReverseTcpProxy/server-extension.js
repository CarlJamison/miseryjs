var net = require("net");
var reverse_tcp_connections = [];
const DEBUG = false;

module.exports = {
    handlers: [
        {   //Write to TCP connection
            returnType: 9,
            handle: (scope, message) => {
                var cust = scope.customers.find(c => c.socketId == scope.socket.id);
                if(!cust) return;

                var serverId = `${message.output.port}:${cust.id}`;
                var server = reverse_tcp_connections[serverId];
                if(!server || !server.jobId) return false;

                var id = message.output.connectionId;
                var connection = server.connections[id];
                
                if(DEBUG) console.log("Recieving: " );
                data = Buffer.from(message.output.data, 'base64');

                if(!connection){
                    var connection = new net.Socket();
                    connection.connect(server.targetPort, server.targetHost, () => {
                        connection.write(data);
                    });

                    connection.on("data", data => {
                        if(DEBUG) console.log("Writing: " + id + " : " + data.toString());

                        scope.clients.to(cust.socketId).emit("add-job-data", { 
                            id: server.jobId.toString(),
                            connection_id: id,
                            data: data.toString('base64') });
                    });
                    
                    connection.on("end", () => {
                        if(reverse_tcp_connections[serverId]){
                            server.connections[id] = null;
                            scope.clients.to(cust.socketId).emit("add-job-data", { 
                                id: server.jobId.toString(),
                                connection_id: id,
                            });
                        }  
                    });

                    connection.on("error", console.log);
                    server.connections[id] = connection;
                }else{
                    connection.write(data);
                }

                if(DEBUG) console.log(id + " : " + data);
                
                return false;
            }
        },
        {   //Initialize
            returnType: 10,
            handle: (scope, msg) => {
                
                var cust = scope.customers.find(c => c.socketId == scope.socket.id);
                if(!cust){
                    return false;
                }

                var serverId = `${msg.output.port}:${cust.id}`;

                var connection = reverse_tcp_connections[serverId]
                if(!connection || connection.jobId){
                    return false;  //Either not a valid server or already created
                }

                connection.jobId = msg.output.jobId;
                scope.controllers.emit('echo', `Reverse TCP Proxy is initialized and running on agent port: ${msg.output.port}`);
            }
        }
    ],
    listeners:[
        {
            //Create placeholder server
            name: 'create-reverse-tcp-server',
            handle: (scope, msg) => {
                var cust = scope.customers.find(c => c.id == msg.id);

                if(reverse_tcp_connections[`${msg.args[2]}:${msg.id}`]){
                    scope.socket.emit('echo', 'Proxy already exists');
                    return;
                }

                if(cust){
                    reverse_tcp_connections[`${msg.args[2]}:${msg.id}`] = {
                        port: msg.args[2],
                        targetHost: msg.args[0],
                        targetPort: msg.args[1],
                        connections: [],
                        jobId: null,
                        id: `${msg.args[2]}:${msg.id}`
                    }
                    scope.clients.to(cust.socketId).emit("run-stream", ["ReverseTcpProxy", msg.args[2]]);
                    scope.socket.emit('echo', 'Reverse Tcp Proxy initiated, awaiting job creation');
                }else{
                    scope.socket.emit('echo', 'Invalid client');
                }
            }
        },
        {
            //Create placeholder server
            name: 'close-reverse-tcp-server',
            handle: (scope, msg) => {

                var server = Object.values(reverse_tcp_connections).find(c => c.port == msg.args[0]);
                if(!server){
                    scope.socket.emit('echo', 'Server does not exist');
                    return;
                }
                
                var cust = scope.customers.find(c => c.id == msg.id);
                if(cust){
                    scope.clients.to(cust.socketId).emit("kill-job", [server.jobId.toString()]);
                    delete reverse_tcp_connections[server.id];
                    scope.socket.emit('echo', `Server port ${msg.args[0]} closed`);
                }else{
                    scope.socket.emit('echo', 'Invalid client');
                }
            }
        },
        {
            //Create placeholder server
            name: 'get-reverse-tcp-servers',
            handle: (scope, msg) => {
                var connections = Object.keys(reverse_tcp_connections);
                if(connections.length){
                    connections.forEach(c => scope.socket.emit('echo', `${c} ${reverse_tcp_connections[c].port}`));
                }else{
                    scope.socket.emit('echo', 'No existing connections');
                }
            }
        }
    ]

}