var net = require("net");
var tcp_connections = [];

module.exports = {
    handlers: [
        {   //Write to TCP connection
            returnType: 5,
            handle: (extension, clientId, message) => {
                data = Buffer.from(message.msg, 'base64');
                extension.tcp_connections[`${jobId}-${clientId}`].write(message.msg);
                return false;
            }
        },
        {   //Initialize
            returnType: 6,
            handle: (extension, clientId, message) => {
                var cust = customers.find(c => c.id == clientId);
                if(!cust){
                    return false;
                }

                var serverId = `${message.port}-${clientId}`;

                var coolServer = tcp_connections[serverId]
                if(!coolServer || coolServer.server){
                    return false;  //Either not a valid server or already created
                }

                coolServer.server = net.createServer(tcp_sock => {
                    var id = uuidv4();
                    coolServer.connections[id] = tcp_sock;

                    tcp_sock.on("data", data => {
                        clients.to(cust.socketId).emit("add-job-data", { 
                            id: coolServer.jobId,
                            connection_id: id, 
                            data: data.toString('base64') });
                    });
                
                    tcp_sock.on("end", () => {
                        extension.tcp_connections[serverId].connections[id] = null;
                    });
                });

                coolServer.server.listen(port, () => {
                    console.log(`TCP is initilized and running on port: ${port}`);
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
                    tcp_connections[`${msg.args[0]}-${msg.id}`] = {
                        serverPort: 0, //TODO decide on server side port,
                        clientPort: msg.args[0],
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